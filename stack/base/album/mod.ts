import type { BaseClient } from "../mod.ts";
import type { LooseType } from "@vyline/loose-types";

export const ALBUM_CHANNEL_ID = "1375220249";

export interface AlbumInfo {
  albumId: string;
  chatId: string;
  title?: string;
  photoCount?: number;
  createTime?: number;
  updateTime?: number;
}

export interface AlbumPhoto {
  id?: string | number;
  photoId?: string | number;
  oid?: string;
  obsResourceId?: { oid?: string; svc?: string; sid?: string };
  resourceType?: string;
  width?: number;
  height?: number;
}

export type AlbumsResponse = {
  code?: number;
  message?: string;
  result?: { albums: AlbumInfo[]; cursor?: string; nextCursor?: string; hasMore?: boolean };
};

export type AlbumPhotosResponse = {
  code?: number;
  message?: string;
  result?: { photos: AlbumPhoto[]; nextCursor?: string };
};

export type AlbumPhotoCreateInput = {
  obsResourceId: { oid: string; sid?: string; svc?: string };
  width: number;
  height: number;
  shotTime?: number;
  resourceType?: "IMAGE" | "VIDEO" | string;
};

export type AlbumResponse<T = LooseType> = {
  code: number;
  message?: string;
  result: T | null;
};

export function buildAlbumUrl(
  endpoint: string,
  path: string,
  query: Record<string, string | number | undefined> = {},
): string {
  const url = new URL(`https://${endpoint}/ext/album${path}`);
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  return url.toString();
}

const ALBUM_GATEWAY = "legy-jp.line-apps.com";
const ALBUM_OBS = "obs-jp.line-apps.com";

/** LINE Album JSON REST client (iOS 26.12.1 observed API). */
export class Album {
  private readonly client: BaseClient;
  private static readonly CHANNEL_ID = "1375220249";

  constructor(client: BaseClient) {
    this.client = client;
  }

  private async channelToken(): Promise<string> {
    return this.client.channelTokens.get(ALBUM_CHANNEL_ID, { approve: true });
  }

  private async json<T extends { code?: number; message?: string }>(
    path: string,
    query: Record<string, string | number | undefined>,
    extraHeaders: Record<string, string> = {},
    body?: unknown,
  ): Promise<T> {
    const mid = this.client.profile?.mid;
    if (!mid) throw new Error("Album API requires a logged-in profile");
    const response = await this.client.fetch(buildAlbumUrl(ALBUM_GATEWAY, path, query), {
      method: "POST",
      headers: {
        ...this.client.request.getHeader("GET"),
        accept: "application/json",
        "content-type": "application/json; charset=UTF-8",
        "X-Line-ChannelToken": await this.channelToken(),
        "X-Line-Mid": mid,
        ...extraHeaders,
      },
      body: body === undefined ? new Uint8Array() : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`Album ${path} HTTP ${response.status}`);
    const result = (await response.json()) as T;
    if (result.code !== undefined && result.code !== 0) {
      throw new Error(`Album ${path} code=${result.code}: ${result.message ?? "unknown error"}`);
    }
    return result;
  }

  public list(options: { chatId: string; cursor?: string; orderBy?: string; include?: string } ): Promise<AlbumsResponse> {
    return this.json("/api/v6/albums", {
      cursor: options.cursor ?? "",
      orderBy: options.orderBy ?? "createTimeDesc",
      include: options.include ?? "",
    }, { "X-Line-Chat-Id": options.chatId, "x-lhm": "GET" });
  }

  public preview(options: { chatId: string; pageSize?: number; thumbnailCount?: number; viewType?: string }) {
    return this.json("/api/v6/albums/preview", {
      pageSize: options.pageSize ?? 2,
      thumbnailCount: options.thumbnailCount ?? 1,
      viewType: options.viewType ?? "chatMenu",
    }, { "X-Line-Chat-Id": options.chatId, "x-lhm": "GET" });
  }

  public create(options: { chatId: string; title: string; modifyDuplicateTitle?: boolean }) {
    return this.json("/api/v6/albums/create", {
      modifyDuplicateTitle: options.modifyDuplicateTitle === false ? "false" : "true",
    }, { "X-Line-Chat-Id": options.chatId, "x-lhm": "POST" }, { title: options.title });
  }

  public update(options: { chatId: string; albumId: string | number; title: string }) {
    return this.json(`/api/v6/albums/${encodeURIComponent(String(options.albumId))}/update`, {}, {
      "X-Line-Chat-Id": options.chatId,
      "x-lhm": "POST",
    }, { title: options.title });
  }

  public delete(options: { chatId: string; albumId: string | number }) {
    return this.json(`/api/v6/albums/${encodeURIComponent(String(options.albumId))}/delete`, {}, {
      "X-Line-Chat-Id": options.chatId,
      "x-lhm": "POST",
    });
  }

  public share(options: { chatId: string; albumId: string | number }) {
    return this.json(`/api/v6/albums/${encodeURIComponent(String(options.albumId))}/share`, {}, {
      "X-Line-Chat-Id": options.chatId,
      "x-lhm": "POST",
    });
  }

  public photos(options: {
    chatId: string;
    albumId: string | number;
    cursor?: string;
    pageSize?: number;
    orderBy?: string;
    include?: string;
    filterType?: string;
    targetUser?: string;
  }): Promise<AlbumPhotosResponse> {
    return this.json(
      `/api/v6/albums/${encodeURIComponent(String(options.albumId))}/photos`,
      {
        cursor: options.cursor ?? "",
        pageSize: options.pageSize ?? 100,
        orderBy: options.orderBy ?? "createTimeDesc",
        include: options.include ?? "album,countLimits",
        filterType: options.filterType ?? "all",
        targetUser: options.targetUser,
      },
      { "X-Line-Chat-Id": options.chatId, "x-lhm": "GET" },
    );
  }

  public addPhotos(options: { chatId: string; albumId: string | number; photos: AlbumPhotoCreateInput[] }) {
    const photos = options.photos.map((photo) => ({
      ...photo,
      obsResourceId: {
        sid: "a",
        svc: "album",
        ...photo.obsResourceId,
      },
    }));
    return this.json(`/api/v6/albums/${encodeURIComponent(String(options.albumId))}/photos/create`, {}, {
      "X-Line-Chat-Id": options.chatId,
      "x-lhm": "POST",
    }, { photos });
  }

  public deletePhotos(options: { chatId: string; albumId: string | number; photoIds: Array<string | number> }) {
    return this.json(`/api/v6/albums/${encodeURIComponent(String(options.albumId))}/photos/delete`, {}, {
      "X-Line-Chat-Id": options.chatId,
      "x-lhm": "POST",
    }, { photoIds: options.photoIds.map(String) });
  }

  public async upload(options: { chatId: string; albumId: string | number; oid: string; data: Blob }) {
    const params = {
      ver: "2.0",
      type: "image",
      name: `${options.oid}.jpeg`,
    };
    const response = await this.client.fetch(
      `https://${ALBUM_OBS}/r/album/a/${encodeURIComponent(options.oid)}`,
      {
        method: "POST",
        headers: {
          ...this.client.request.getHeader("POST"),
          "X-Line-ChannelToken": await this.channelToken(),
          "X-Line-Mid": options.chatId,
          "X-Line-Album": String(options.albumId),
          "Upload-Draft-Interop-Version": "6",
          "Upload-Complete": "?1",
          "content-type": "application/octet-stream",
          "content-length": String(options.data.size),
          "x-obs-params": Buffer.from(JSON.stringify(params)).toString("base64"),
        },
        body: options.data,
      },
    );
    if (!response.ok) throw new Error(`Album upload ${options.oid} HTTP ${response.status}`);
    return { oid: response.headers.get("x-obs-oid") ?? options.oid };
  }

  public async download(options: {
    chatId: string;
    albumId: string | number;
    oid: string;
    mediaType?: "image" | "video";
  }): Promise<Response> {
    const suffix = options.mediaType === "video" ? "m1200" : "m1200";
    const response = await this.client.fetch(
      `https://${ALBUM_OBS}/r/album/a/${encodeURIComponent(options.oid)}/${suffix}`,
      {
        method: "GET",
        headers: {
          ...this.client.request.getHeader("GET"),
          "X-Line-ChannelToken": await this.channelToken(),
          "X-Line-Mid": options.chatId,
          "X-Line-Album": String(options.albumId),
        },
      },
    );
    if (!response.ok) throw new Error(`Album media ${options.oid} HTTP ${response.status}`);
    return response;
  }

  private async headers(): Promise<Record<string, string>> {
    const token = await this.client.channelTokens.get(Album.CHANNEL_ID, { approve: true });
    return {
      "x-line-bdbtemplateversion": "v1",
      "x-lsr": "JP",
      "user-agent": this.client.request.userAgent,
      "x-line-channeltoken": token,
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
    const url = `https://${this.client.request.endpoint}/ext/album${options.path.startsWith("/") ? options.path : `/${options.path}`}${suffix}`;
    const invoke = async () =>
      this.client.fetch(url, {
        method: options.method ?? (options.body === undefined ? "GET" : "POST"),
        headers: await this.headers(),
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      });
    let response = await invoke();
    if (response.status === 401) {
      await this.client.channelTokens.reissue(Album.CHANNEL_ID, true);
      response = await invoke();
    }
    return (await response.json()) as AlbumResponse<T>;
  }
}
