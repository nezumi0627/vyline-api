import type { BaseClient } from "../mod.ts";
import type { LooseType } from "@vyline/loose-types";

export type AlbumResponse<T = LooseType> = {
  code: number;
  message?: string;
  result: T | null;
};

/** LINE の Album REST 入口。エンドポイントの詳細はサーバー側で管理する。 */
export class Album {
  private readonly client: BaseClient;
  private token?: string;

  constructor(client: BaseClient) {
    this.client = client;
  }

  private async headers(): Promise<Record<string, string>> {
    if (!this.token) {
      this.token = (
        await this.client.channel.approveChannelAndIssueChannelToken({ channelId: "1375220249" })
      ).channelAccessToken;
    }
    return {
      "x-line-bdbtemplateversion": "v1",
      "x-lsr": "JP",
      "user-agent": this.client.request.userAgent,
      "x-line-channeltoken": this.token,
      "x-line-mid": this.client.profile!.mid,
      "x-line-access": this.client.authToken,
      "content-type": "application/json; charset=UTF-8",
      accept: "application/json",
    };
  }

  /** Album API の低レベル入口。個人／グループは chatMid を body に含めて指定する。 */
  public async call<T = LooseType>(options: {
    path: string;
    method?: "GET" | "POST" | "PUT" | "DELETE";
    query?: Record<string, string | number | undefined>;
    body?: LooseType;
  }): Promise<AlbumResponse<T>> {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(options.query ?? {})) {
      if (value !== undefined) query.set(key, String(value));
    }
    const suffix = query.size ? `?${query}` : "";
    const response = await this.client.fetch(
      `https://${this.client.request.endpoint}/ext/album${options.path.startsWith("/") ? options.path : `/${options.path}`}${suffix}`,
      {
        method: options.method ?? (options.body === undefined ? "GET" : "POST"),
        headers: await this.headers(),
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      },
    );
    return (await response.json()) as AlbumResponse<T>;
  }
}
