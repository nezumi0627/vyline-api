import type { BaseClient } from "../core/mod.ts";

export type ChannelTokenIssuance = "issue" | "approve-and-issue";

type PersistedChannelToken = {
  channelId: string;
  channelAccessToken: string;
  issuedAt: string;
  lastUsedAt: string;
  issuance: ChannelTokenIssuance;
  reissuedAt?: string;
};

function storageKey(channelId: string): string {
  return `channelToken:${channelId}`;
}

function accessTokenOf(value: unknown): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const row = value as { channelAccessToken?: unknown; token?: unknown };
  // Gateway REST APIs require channelAccessToken. `token` is only a compatibility
  // fallback for older channel responses and must not be preferred.
  if (typeof row.channelAccessToken === "string" && row.channelAccessToken) {
    return row.channelAccessToken;
  }
  return typeof row.token === "string" && row.token ? row.token : undefined;
}

/** Per-account channel-token lifecycle backed by the client's account storage. */
export class ChannelTokenManager {
  readonly client: BaseClient;
  #memory = new Map<string, PersistedChannelToken>();
  #inflight = new Map<string, Promise<string>>();

  constructor(client: BaseClient) {
    this.client = client;
  }

  async get(
    channelId: string,
    options: { force?: boolean; approve?: boolean } = {},
  ): Promise<string> {
    if (!options.force) {
      const cached = this.#memory.get(channelId) ?? (await this.#read(channelId));
      if (cached?.channelAccessToken) {
        cached.lastUsedAt = new Date().toISOString();
        this.#memory.set(channelId, cached);
        void this.client.storage.set(storageKey(channelId), cached);
        return cached.channelAccessToken;
      }
    }

    const current = this.#inflight.get(channelId);
    if (current) return current;
    const pending = this.#issue(channelId, options.approve ?? false, options.force ?? false).finally(
      () => this.#inflight.delete(channelId),
    );
    this.#inflight.set(channelId, pending);
    return pending;
  }

  async invalidate(channelId: string): Promise<void> {
    this.#memory.delete(channelId);
    await this.client.storage.delete(storageKey(channelId));
  }

  async reissue(channelId: string, approve = false): Promise<string> {
    await this.invalidate(channelId);
    return this.get(channelId, { force: true, approve });
  }

  async #read(channelId: string): Promise<PersistedChannelToken | undefined> {
    const value = await this.client.storage.get(storageKey(channelId));
    if (!value || typeof value !== "object") return undefined;
    const row = value as unknown as PersistedChannelToken;
    if (row.channelId !== channelId || typeof row.channelAccessToken !== "string") return undefined;
    this.#memory.set(channelId, row);
    return row;
  }

  async #issue(channelId: string, approve: boolean, reissue: boolean): Promise<string> {
    let response: unknown;
    let issuance: ChannelTokenIssuance = "issue";
    try {
      response = await this.client.channel.issueChannelToken({ channelId });
    } catch (error) {
      if (!approve) throw error;
      issuance = "approve-and-issue";
      response = await this.client.channel.approveChannelAndIssueChannelToken({ channelId });
    }
    let token = accessTokenOf(response);
    if (!token && approve && issuance === "issue") {
      issuance = "approve-and-issue";
      response = await this.client.channel.approveChannelAndIssueChannelToken({ channelId });
      token = accessTokenOf(response);
    }
    if (!token) throw new Error(`channel ${channelId} returned no channelAccessToken`);

    const now = new Date().toISOString();
    const saved: PersistedChannelToken = {
      channelId,
      channelAccessToken: token,
      issuedAt: now,
      lastUsedAt: now,
      issuance,
      ...(reissue ? { reissuedAt: now } : {}),
    };
    this.#memory.set(channelId, saved);
    await this.client.storage.set(storageKey(channelId), saved);
    return token;
  }
}
