import { describe, expect, test } from "bun:test";
import { ChannelTokenManager } from "./mod.ts";

function fakeClient(options: { issueFails?: boolean; emptyIssue?: boolean } = {}) {
  const data = new Map<string, unknown>();
  let issues = 0;
  let approvals = 0;
  const client = {
    storage: {
      async get(key: string) {
        return data.get(key);
      },
      async set(key: string, value: unknown) {
        data.set(key, value);
      },
      async delete(key: string) {
        data.delete(key);
      },
    },
    channel: {
      async issueChannelToken({ channelId }: { channelId: string }) {
        issues += 1;
        if (options.issueFails) throw new Error("approval required");
        if (options.emptyIssue) return {};
        return { token: "wrong-compat-token", channelAccessToken: `access-${channelId}-${issues}` };
      },
      async approveChannelAndIssueChannelToken({ channelId }: { channelId: string }) {
        approvals += 1;
        return { channelAccessToken: `approved-${channelId}-${approvals}` };
      },
    },
  };
  return { client: client as never, data, counts: () => ({ issues, approvals }) };
}

describe("ChannelTokenManager", () => {
  test("persists and reuses channelAccessToken", async () => {
    const fake = fakeClient();
    const first = new ChannelTokenManager(fake.client);
    expect(await first.get("1375220249", { approve: true })).toBe("access-1375220249-1");
    expect(await first.get("1375220249", { approve: true })).toBe("access-1375220249-1");

    const restored = new ChannelTokenManager(fake.client);
    expect(await restored.get("1375220249", { approve: true })).toBe("access-1375220249-1");
    expect(fake.counts().issues).toBe(1);
  });

  test("reissue invalidates old token and issues a fresh value", async () => {
    const fake = fakeClient();
    const manager = new ChannelTokenManager(fake.client);
    expect(await manager.get("1341209850")).toBe("access-1341209850-1");
    expect(await manager.reissue("1341209850")).toBe("access-1341209850-2");
    expect(fake.counts().issues).toBe(2);
  });

  test("invalidate removes persisted value", async () => {
    const fake = fakeClient();
    const manager = new ChannelTokenManager(fake.client);
    await manager.get("1655599932");
    await manager.invalidate("1655599932");
    expect(fake.data.has("channelToken:1655599932")).toBe(false);
  });

  test("falls back to approve-and-issue only when allowed", async () => {
    const fake = fakeClient({ issueFails: true });
    const manager = new ChannelTokenManager(fake.client);
    await expect(manager.get("1657618623")).rejects.toThrow("approval required");
    expect(await manager.get("1657618623", { approve: true })).toBe("approved-1657618623-1");
  });

  test("falls back when issue succeeds without a usable token", async () => {
    const fake = fakeClient({ emptyIssue: true });
    const manager = new ChannelTokenManager(fake.client);
    expect(await manager.get("1375220249", { approve: true })).toBe("approved-1375220249-1");
  });
});
