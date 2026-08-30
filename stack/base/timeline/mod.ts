// deno-lint-ignore-file no-explicit-any
import { Buffer } from "node:buffer";
import crypto from "node:crypto";
import type { BaseClient } from "../mod.ts";
import type { LooseType } from "@vyline/loose-types";

const CONTENT_GATEWAY = "legy-jp.line-apps.com";

export type TimelineResponse<T = LooseType> = {
  code: number;
  message: string;
  result: T;
};

export class Timeline {
  protected timelineToken: string | undefined;
  public timelineHeaders: Record<string, string | undefined> = {};
  client: BaseClient;
  constructor(client: BaseClient) {
    this.client = client;
  }

  public async initTimeline() {
    this.timelineToken = await this.client.channelTokens.get("1341209850", { approve: true });
    this.timelineHeaders = {
      "x-line-bdbtemplateversion": "v1",
      "x-lsr": "JP",
      "user-agent": this.client.request.userAgent,
      "x-line-channeltoken": this.timelineToken,
      "accept-encoding": "gzip",
      "x-line-global-config": "discover.enable=true; follow.enable=true; reboot.phase=scenario",
      "x-line-mid": this.client.profile!.mid,
      "x-line-access": this.client.authToken,
      "content-type": "application/json; charset=UTF-8",
      "x-line-application": this.client.request.systemType,
      "x-lal": "ja_JP",
      "x-lpv": "1",
    };
  }

  public async createPost(options: {
    homeId: string;
    text?: string;
    sharedPostId?: string;
    textSizeMode?: "AUTO" | "NORMAL";
    backgroundColor?: string;
    textAnimation?: "NONE" | "SLIDE" | "ZOOM" | "BUZZ" | "BOUNCE" | "BLINK";
    readPermissionType?: "ALL" | "FRIEND" | "GROUP" | "EVENT" | "NONE";
    readPermissionGids?: string[];
    holdingTime?: number;
    stickerIds?: string[];
    stickerPackageIds?: string[];
    locationLatitudes?: number[];
    locationLongitudes?: number[];
    locationNames?: string[];
    mediaObjectIds?: string[];
    mediaObjectTypes?: string[];
    sourceType?: string;
    contents?: LooseType;
    postInfo?: LooseType;
  }): Promise<TimelineResponse> {
    await this.initTimeline();
    const {
      homeId,
      text,
      sharedPostId,
      textSizeMode,
      backgroundColor,
      textAnimation,
      readPermissionType,
      readPermissionGids,
      holdingTime,
      stickerIds,
      stickerPackageIds,
      locationLatitudes,
      locationLongitudes,
      locationNames,
      mediaObjectIds,
      mediaObjectTypes,
      sourceType,
      contents: suppliedContents,
      postInfo: suppliedPostInfo,
    } = {
      textSizeMode: "NORMAL",
      backgroundColor: "#FFFFFF",
      textAnimation: "NONE",
      readPermissionType: "ALL",
      sourceType: "GROUPHOME",
      readPermissionGids: [],
      stickerIds: [],
      stickerPackageIds: [],
      locationLatitudes: [],
      locationLongitudes: [],
      locationNames: [],
      mediaObjectIds: [],
      mediaObjectTypes: [],
      ...options,
    };
    if (homeId[0] === "u") {
      throw new Error("Not support oto");
    }
    const params = new URLSearchParams({ homeId, sourceType, ruid: crypto.randomUUID() });
    const postInfo: LooseType = suppliedPostInfo ?? {
      readPermission: { homeID: homeId, type: readPermissionType, gids: readPermissionGids },
    };
    const stickers: {
      id: string;
      packageId: string;
      packageVersion: number;
      hasAnimation: boolean;
      hasSound: boolean;
      stickerResourceType: string;
    }[] = [];
    const locations: {
      latitude: number;
      longitude: number;
      name: string;
    }[] = [];
    const medias: { objectId: string; type: string; obsFace: string }[] = [];
    stickerIds.forEach((stickerId, stickerIndex) => {
      stickers.push({
        id: stickerId,
        packageId: stickerPackageIds[stickerIndex],
        packageVersion: 1,
        hasAnimation: true,
        hasSound: true,
        stickerResourceType: "ANIMATION",
      });
    });
    locationLatitudes.forEach((locationLatitude, locatioIndex) => {
      locations.push({
        latitude: locationLatitude,
        longitude: locationLongitudes[locatioIndex],
        name: locationNames[locatioIndex],
      });
    });
    mediaObjectIds.forEach((mediaObjectId, mediaIndex) => {
      medias.push({
        objectId: mediaObjectId,
        type: mediaObjectTypes[mediaIndex],
        obsFace: "[]",
      });
    });
    const contents: LooseType = suppliedContents ?? {
      textMeta: [],
      sticonMetas: [],
      contentsStyle: {
        textStyle: {
          textSizeMode: textSizeMode,
          backgroundColor: backgroundColor,
          textAnimation: textAnimation,
        },
        mediaStyle: { displayType: "GRID_1_A" },
      },
      stickers: stickers,
      locations: locations,
      media: medias.map((media) => ({
        objectId: media.objectId,
        type: media.type,
        serviceName: "privnote",
        obsNamespace: "post",
      })),
    };
    if (typeof holdingTime !== "undefined") {
      postInfo.holdingTime = holdingTime;
    }
    if (typeof text !== "undefined") {
      contents.text = text;
    }
    if (typeof sharedPostId !== "undefined") {
      contents.sharedPostId = sharedPostId;
    }
    const data = { postInfo, contents, sourceType, relatedContents: {} };
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "POST",
    };
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/post/create.json?${params}`,
        { headers, body: JSON.stringify(data), method: "POST" },
      )
      .then((r) => r.json());
  }

  public async deletePost(options: { homeId: string; postId: string }): Promise<TimelineResponse> {
    await this.initTimeline();
    const { homeId, postId } = { ...options };
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "GET",
    };
    const params = new URLSearchParams({
      homeId,
      postId,
    });
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/post/delete.json?${params}`,
        { headers, method: "POST" },
      )
      .then((r) => r.json());
  }

  public async getPost(options: { homeId: string; postId: string }): Promise<TimelineResponse> {
    await this.initTimeline();
    const { homeId, postId } = { ...options };
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "GET",
    };
    const params = new URLSearchParams({
      homeId,
      postId,
    });
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/post/get.json?${params}`,
        { headers },
      )
      .then((r) => r.json());
  }

  public async listPost(options: {
    homeId: string;
    postId?: string;
    updatedTime?: number;
    sourceType?: string;
    postLimit?: number;
    showVideoPostsOnly?: boolean;
  }): Promise<TimelineResponse> {
    await this.initTimeline();
    const { homeId, postId, updatedTime, sourceType, postLimit, showVideoPostsOnly } = {
      sourceType: "GROUPHOME",
      postLimit: 20,
      showVideoPostsOnly: false,
      ...options,
    };
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "GET",
    };
    const data: Record<string, string> = {
      homeId,
      sourceType,
      likeLimit: "0",
      commentLimit: "0",
      showVideoPostsOnly: String(showVideoPostsOnly),
      postLimit: String(postLimit),
    };
    if (postId) {
      data.postId = postId;
    }
    if (updatedTime) {
      data.updatedTime = updatedTime.toString();
    }
    const params = new URLSearchParams(data);
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/post/list.json?${params}`,
        { headers },
      )
      .then((r) => r.json());
  }

  public async updatePost(options: {
    homeId: string;
    postId: string;
    text?: string;
    sharedPostId?: string;
    textSizeMode?: "AUTO" | "NORMAL";
    backgroundColor?: string;
    textAnimation?: "NONE" | "SLIDE" | "ZOOM" | "BUZZ" | "BOUNCE" | "BLINK";
    holdingTime?: number;
    stickerIds?: string[];
    stickerPackageIds?: string[];
    locationLatitudes?: number[];
    locationLongitudes?: number[];
    locationNames?: string[];
    mediaObjectIds?: string[];
    mediaObjectTypes?: string[];
    contents?: LooseType;
  }): Promise<TimelineResponse> {
    await this.initTimeline();
    const {
      homeId,
      postId,
      text,
      sharedPostId,
      textSizeMode,
      backgroundColor,
      textAnimation,
      holdingTime,
      stickerIds,
      stickerPackageIds,
      locationLatitudes,
      locationLongitudes,
      locationNames,
      mediaObjectIds,
      mediaObjectTypes,
      contents: suppliedContents,
    } = {
      textSizeMode: "NORMAL",
      backgroundColor: "#FFFFFF",
      textAnimation: "NONE",
      stickerIds: [],
      stickerPackageIds: [],
      locationLatitudes: [],
      locationLongitudes: [],
      locationNames: [],
      mediaObjectIds: [],
      mediaObjectTypes: [],
      ...options,
    };
    if (!homeId) {
      throw new Error("homeId is required");
    }
    if (!postId) {
      throw new Error("postId is required");
    }
    const postInfo: LooseType = {
      postId: postId,
      editableContents: ["ALL"],
      readPermission: {
        homeID: homeId,
      },
    };
    const stickers: {
      id: string;
      packageId: string;
      packageVersion: number;
      hasAnimation: boolean;
      hasSound: boolean;
      stickerResourceType: string;
    }[] = [];
    const locations: {
      latitude: number;
      longitude: number;
      name: string;
    }[] = [];
    const medias: { objectId: string; type: string; obsFace: string }[] = [];
    stickerIds.forEach((stickerId, stickerIndex) => {
      stickers.push({
        id: stickerId,
        packageId: stickerPackageIds[stickerIndex],
        packageVersion: 1,
        hasAnimation: true,
        hasSound: true,
        stickerResourceType: "ANIMATION",
      });
    });
    locationLatitudes.forEach((locationLatitude, locatioIndex) => {
      locations.push({
        latitude: locationLatitude,
        longitude: locationLongitudes[locatioIndex],
        name: locationNames[locatioIndex],
      });
    });
    mediaObjectIds.forEach((mediaObjectId, mediaIndex) => {
      medias.push({
        objectId: mediaObjectId,
        type: mediaObjectTypes[mediaIndex],
        obsFace: "[]",
      });
    });
    const contents: LooseType = suppliedContents ?? {
      sticonMetas: [],
      contentsStyle: {
        textStyle:
          textSizeMode || textAnimation
            ? {
                textSizeMode: textSizeMode,
                textAnimation: textAnimation,
              }
            : {},
        stickerStyle: backgroundColor
          ? {
              backgroundColor: backgroundColor,
            }
          : {},
        mediaStyle: {},
      },
      stickers: stickers,
      textMeta: [],
      locations: locations,
      media: medias,
    };
    if (typeof holdingTime !== "undefined") {
      postInfo.holdingTime = holdingTime;
    }
    if (typeof text !== "undefined") {
      contents.text = text;
    }
    if (typeof sharedPostId !== "undefined") {
      contents.sharedPostId = sharedPostId;
    }
    const data = { postInfo: postInfo, contents: contents };
    const params = new URLSearchParams({
      homeId: homeId,
    });
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "POST",
    };
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/post/update.json?${params}`,
        { headers, body: JSON.stringify(data), method: "POST" },
      )
      .then((r) => r.json());
  }

  public async likePost(options: {
    contentId: string; // postId
    homeId: string;
    likeType?: "1003" | "1001" | "1002" | "1004" | "1006" | "1005"; // 1003: GOOD, 1001: LOVE, 1002: FUNNY, 1004: AMAZING, 1006: SAD, 1005: SURPRISED
    sourceType?: string;
  }): Promise<TimelineResponse> {
    await this.initTimeline();
    const { contentId, homeId, likeType, sourceType } = {
      likeType: "1003",
      sourceType: "GROUPHOME_END",
      ...options,
    };
    const params = new URLSearchParams({
      homeId,
    });
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "POST",
    };
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/like/create.json?${params}`,
        {
          headers,
          method: "POST",
          body: JSON.stringify({
            sourceType,
            likeType,
            contentId,
          }),
        },
      )
      .then((r) => r.json());
  }

  public async unlikePost(options: { contentId: string; homeId: string; sourceType?: string }): Promise<TimelineResponse> {
    await this.initTimeline();
    const params = new URLSearchParams({
      homeId: options.homeId,
      sourceType: options.sourceType ?? "GROUPHOME_END",
      contentId: options.contentId,
    });
    return await this.client.fetch(
      `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/like/cancel.json?${params}`,
      { headers: { ...this.timelineHeaders, "x-lhm": "POST" }, method: "POST" },
    ).then((r) => r.json());
  }

  public async getLike(options: { contentId: string; homeId: string }): Promise<TimelineResponse> {
    await this.initTimeline();
    const params = new URLSearchParams({ contentId: options.contentId, parentType: "activity", homeId: options.homeId });
    return await this.client.fetch(
      `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/like/get.json?${params}`,
      { headers: { ...this.timelineHeaders, "x-lhm": "GET" } },
    ).then((r) => r.json());
  }

  public async listLikes(options: { contentId: string; homeId: string; sourceType?: string }): Promise<TimelineResponse> {
    await this.initTimeline();
    const params = new URLSearchParams({
      homeId: options.homeId,
      includes: "ALL,GROUPED,STATS",
      sourceType: options.sourceType ?? "TALKROOM",
      contentId: options.contentId,
    });
    return await this.client.fetch(
      `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/like/getList.json?${params}`,
      { headers: { ...this.timelineHeaders, "x-lhm": "GET" } },
    ).then((r) => r.json());
  }

  public async createComment(options: {
    contentId: string; // postId
    commentText: string;
    homeId: string;
    sourceType?: string;
    contentsList?: LooseType[];
  }): Promise<TimelineResponse> {
    await this.initTimeline();
    const { contentId, commentText, homeId, sourceType, contentsList } = {
      sourceType: "GROUPHOME_END",
      contentsList: [],
      ...options,
    };
    const params = new URLSearchParams({
      sourceType,
      homeId,
    });
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "POST",
    };
    const body = {
      commentText,
      contentId,
      contentsList,
    };
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/comment/create.json?${params}`,
        {
          headers,
          method: "POST",
          body: JSON.stringify(body),
        },
      )
      .then((r) => r.json());
  }

  public async sharePost(options: {
    postId: string;
    homeId: string;
  }): Promise<TimelineResponse> {
    const { postId, homeId } = {
      ...options,
    };
    await this.initTimeline();
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "POST",
    };
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/post/share.json?${new URLSearchParams({ homeId, ruid: crypto.randomUUID() })}`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({ postId }),
        },
      )
      .then((r) => r.json());
  }

  public async getGroupHomeUpdates(revision: number): Promise<TimelineResponse> {
    await this.initTimeline();
    const headers = {
      ...this.timelineHeaders,
      "x-lhm": "GET",
    };
    return await this.client
      .fetch(
        `https://${CONTENT_GATEWAY}/ext/note/nt/api/v57/grouphome/isnew.json?${new URLSearchParams({ revision: String(revision) })}`,
        {
          method: "POST",
          headers,
          body: "",
        },
      )
      .then((r) => r.json());
  }

  /** Upload Note post media using the current iOS/iPad OBS path. */
  public async uploadNoteMedia(
    type: "image" | "video",
    data: Blob,
  ): Promise<{ objId: string; objHash: string }> {
    await this.initTimeline();
    const requestedOid = crypto.randomUUID().replaceAll("-", "");
    const extension = type === "video" ? "mp4" : "jpg";
    const uploadName = `${crypto.randomUUID().toUpperCase()}.${extension}`;
    const params = {
      ver: "2.0",
      type,
      name: uploadName,
    };
    const res: Response = await this.client.fetch(
      `https://obs-jp.line-apps.com/r/privnote/post/${requestedOid}`,
      {
        method: "POST",
        headers: {
          Accept: "*/*",
          "Accept-Language": "ja",
          "X-Line-ChannelToken": this.timelineToken!,
          "X-Line-Application": this.timelineHeaders["x-line-application"]!,
          "User-Agent": this.timelineHeaders["user-agent"]!,
          "x-lal": "ja_JP",
          "Upload-Draft-Interop-Version": "6",
          "Upload-Complete": "?1",
          "content-type": "application/octet-stream",
          "content-length": String(data.size),
          "x-obs-params": Buffer.from(JSON.stringify(params)).toString("base64"),
        },
        body: data,
      },
    );
    if (res.status !== 201) {
      const detail = (await res.text())
        .slice(0, 500)
        .replace(/[A-Za-z0-9+/_=-]{40,}/g, "<redacted>");
      throw new Error(`Note media upload failed: HTTP ${res.status}${detail ? ` ${detail}` : ""}`);
    }
    return {
      objId: res.headers.get("x-obs-oid") ?? requestedOid,
      objHash: res.headers.get("x-obs-hash") ?? "",
    };
  }

  /**
   * Uploads an image into the myhome comment OBS space (`myhome/cmt`) for use in
   * a Note comment's `contentsList` media entry (`{ categoryId: "media", extData:
   * { objectId, type: "PHOTO", obsNamespace: "cmt", serviceName: "myhome", … } }`).
   *
   * Unlike {@link uploadNoteMedia}, the server assigns the object id here, so the
   * returned `objId` comes from the response `x-obs-oid` — reusing a client-chosen
   * id would leave the comment referencing a non-existent object (renders broken).
   * Note comments accept images only (video comments are not supported by LINE).
   */
  public async uploadNoteCommentImage(data: Blob): Promise<{ objId: string; objHash: string }> {
    await this.initTimeline();
    const seed = crypto
      .createHash("md5")
      .update(`${this.client.profile!.mid}-${Date.now()}`)
      .digest("hex");
    const res = await this.#uploadObjNhn("myhome/cmt", seed, "image", data);
    return {
      objId: res.headers.get("x-obs-oid") ?? seed,
      objHash: res.headers.get("x-obs-hash") ?? "",
    };
  }

  async #uploadObjNhn(
    obsPath: string,
    oid: string,
    type: "image" | "video",
    data: Blob,
  ): Promise<Response> {
    const contentType = type === "video" ? "video/mp4" : "image/jpeg";
    const params = {
      name: `${oid}.${type === "video" ? "mp4" : "jpg"}`,
      oid,
      type,
      ver: "2.0",
    };
    const body = new Blob([data], { type: contentType });
    const res: Response = await this.client.fetch(
      `https://obs.line-apps.com/${obsPath}/upload.nhn`,
      {
        method: "POST",
        headers: {
          ...this.timelineHeaders,
          "content-type": contentType,
          "content-length": String(body.size),
          "x-obs-params": Buffer.from(JSON.stringify(params)).toString("base64"),
        },
        body,
      },
    );
    if (res.status !== 201) {
      throw new Error(`Note media upload failed (${obsPath}): HTTP ${res.status}`);
    }
    return res;
  }
}
