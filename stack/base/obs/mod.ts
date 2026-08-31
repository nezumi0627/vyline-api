import { Buffer } from "node:buffer";
import { createReadStream, openAsBlob } from "node:fs";
import { open, rm, stat } from "node:fs/promises";
import { type BaseClient, InternalError } from "../core/mod.js";
import { MimeType } from "./mime.js";
import crypto from "node:crypto";
import type { ContentType, Message } from "@vyline/line-types";
import { writeStruct } from "../thrift/readwrite/write.js";
// @ts-types="thrift-types"
import * as thrift from "thrift";

export type ObjType = "image" | "gif" | "video" | "audio" | "file";
export interface ObsMetadata {
  status: string;
  name: string;
  mime: string;
  type: string;
  hash: string;
  cksum: string;
  size: number | string;
  ctimeMillis: number;
  imageDetails?: {
    format: string;
    height: number;
    width: number;
    signature: string;
  };
  videoMp4Details?: {
    size: number;
    durationMillis: number;
    height: number;
    width: number;
    format: string;
    status: string;
  };
  audioM4aDetails?: {
    size: number;
    durationMillis: number;
    format: string;
    status: string;
  };
  svc: string;
  offset: number;
  ctime: string;
  oid: string;
  userid: string;
  sid: string;
}

export interface E2eeMediaFileResult {
  path: string;
  size: number;
}

export interface DownloadedE2eeMediaFile extends E2eeMediaFileResult {
  fileName: string;
  contentType: string;
}

export type E2eeMediaBeforeWrite = (
  nextTotalBytes: number,
  pendingBytes: number,
) => void | Promise<void>;

interface E2eeMediaKeys {
  encKey: Buffer;
  macKey: Buffer;
  nonce: Buffer;
}

const E2EE_MEDIA_TAG_BYTES = 32;
const DEFAULT_MAX_E2EE_MEDIA_BYTES = 10 * 1024 * 1024 * 1024;

function assertMediaByteLimit(maxBytes: number): void {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes <= 0 ||
    maxBytes > DEFAULT_MAX_E2EE_MEDIA_BYTES
  ) {
    throw new Error("media byte limit is invalid");
  }
}

async function writeAll(
  handle: Awaited<ReturnType<typeof open>>,
  bytes: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesWritten } = await handle.write(bytes.subarray(offset));
    if (bytesWritten <= 0) throw new Error("media file write made no progress");
    offset += bytesWritten;
  }
}

/** Encrypt one media file with bounded buffers and append LINE's HMAC tag. */
export async function encryptE2eeMediaFile(
  sourcePath: string,
  targetPath: string,
  keys: E2eeMediaKeys,
  maxBytes = DEFAULT_MAX_E2EE_MEDIA_BYTES,
  signal?: AbortSignal,
): Promise<E2eeMediaFileResult> {
  assertMediaByteLimit(maxBytes);
  signal?.throwIfAborted();
  const sourceInfo = await stat(sourcePath);
  if (
    !sourceInfo.isFile() ||
    !Number.isSafeInteger(sourceInfo.size) ||
    sourceInfo.size <= 0 ||
    sourceInfo.size > maxBytes
  ) {
    throw new Error("media source size is invalid");
  }
  const cipher = crypto.createCipheriv("aes-256-ctr", keys.encKey, keys.nonce);
  const hmac = crypto.createHmac("sha256", keys.macKey);
  let output: Awaited<ReturnType<typeof open>> | undefined;
  let inputBytes = 0;
  let outputBytes = 0;
  let outputOpen = false;
  let targetCreated = false;
  try {
    signal?.throwIfAborted();
    output = await open(targetPath, "wx", 0o600);
    outputOpen = true;
    targetCreated = true;
    for await (const chunk of createReadStream(sourcePath, { signal })) {
      signal?.throwIfAborted();
      const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
      inputBytes += bytes.byteLength;
      if (inputBytes > sourceInfo.size || inputBytes > maxBytes) {
        throw new Error("media source changed or exceeded its size limit");
      }
      const encrypted = cipher.update(bytes);
      if (encrypted.byteLength > 0) {
        hmac.update(encrypted);
        await writeAll(output, encrypted);
        outputBytes += encrypted.byteLength;
      }
    }
    if (inputBytes !== sourceInfo.size) throw new Error("media source changed while reading");
    const final = cipher.final();
    if (final.byteLength > 0) {
      hmac.update(final);
      await writeAll(output, final);
      outputBytes += final.byteLength;
    }
    const tag = hmac.digest();
    await writeAll(output, tag);
    outputBytes += tag.byteLength;
    await output.close();
    outputOpen = false;
    return { path: targetPath, size: outputBytes };
  } catch (error) {
    if (outputOpen) await output?.close().catch(() => undefined);
    if (targetCreated) await rm(targetPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

/**
 * Authenticate and decrypt an OBS response into an unpublished file. Only the
 * final 32-byte tag and the current network chunk are retained in memory.
 */
export async function decryptE2eeMediaResponseToFile(
  response: Response,
  targetPath: string,
  keys: E2eeMediaKeys,
  maxBytes = DEFAULT_MAX_E2EE_MEDIA_BYTES,
  signal?: AbortSignal,
  beforeWrite?: E2eeMediaBeforeWrite,
): Promise<E2eeMediaFileResult> {
  assertMediaByteLimit(maxBytes);
  signal?.throwIfAborted();
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`media download failed: ${response.status}`);
  }
  if (!response.body) throw new Error("media download returned no body");
  const declaredBytes = Number(response.headers.get("content-length") ?? 0);
  if (
    Number.isFinite(declaredBytes) &&
    declaredBytes > 0 &&
    (declaredBytes < E2EE_MEDIA_TAG_BYTES || declaredBytes > maxBytes + E2EE_MEDIA_TAG_BYTES)
  ) {
    await response.body.cancel().catch(() => undefined);
    throw new Error("encrypted media response size is invalid");
  }

  let output: Awaited<ReturnType<typeof open>> | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let tail = new Uint8Array(0);
  let receivedBytes = 0;
  let outputBytes = 0;
  let outputOpen = false;
  let targetCreated = false;
  let readerDone = false;
  try {
    output = await open(targetPath, "wx", 0o600);
    outputOpen = true;
    targetCreated = true;
    reader = response.body.getReader();
    const decipher = crypto.createDecipheriv("aes-256-ctr", keys.encKey, keys.nonce);
    const hmac = crypto.createHmac("sha256", keys.macKey);
    const consumeCiphertext = async (ciphertext: Uint8Array): Promise<void> => {
      signal?.throwIfAborted();
      if (ciphertext.byteLength === 0) return;
      hmac.update(ciphertext);
      const plain = decipher.update(ciphertext);
      if (plain.byteLength > 0) {
        await beforeWrite?.(outputBytes + plain.byteLength, plain.byteLength);
        signal?.throwIfAborted();
        await writeAll(output!, plain);
        outputBytes += plain.byteLength;
      }
    };
    for (;;) {
      const { done, value } = await reader.read();
      signal?.throwIfAborted();
      if (done) {
        readerDone = true;
        break;
      }
      if (!value || value.byteLength === 0) continue;
      receivedBytes += value.byteLength;
      if (receivedBytes > maxBytes + E2EE_MEDIA_TAG_BYTES) {
        throw new Error("encrypted media response exceeded its size limit");
      }
      if (value.byteLength >= E2EE_MEDIA_TAG_BYTES) {
        await consumeCiphertext(tail);
        await consumeCiphertext(value.subarray(0, value.byteLength - E2EE_MEDIA_TAG_BYTES));
        tail = value.slice(value.byteLength - E2EE_MEDIA_TAG_BYTES);
      } else {
        const joined = new Uint8Array(tail.byteLength + value.byteLength);
        joined.set(tail, 0);
        joined.set(value, tail.byteLength);
        if (joined.byteLength > E2EE_MEDIA_TAG_BYTES) {
          const split = joined.byteLength - E2EE_MEDIA_TAG_BYTES;
          await consumeCiphertext(joined.subarray(0, split));
          tail = joined.slice(split);
        } else {
          tail = joined;
        }
      }
    }
    if (declaredBytes > 0 && receivedBytes !== declaredBytes) {
      throw new Error("encrypted media response ended before its declared size");
    }
    if (tail.byteLength !== E2EE_MEDIA_TAG_BYTES) {
      throw new Error("encrypted media response is missing its authentication tag");
    }
    const expectedTag = hmac.digest();
    if (!crypto.timingSafeEqual(expectedTag, tail)) {
      throw new Error("encrypted media authentication failed");
    }
    const final = decipher.final();
    if (final.byteLength > 0) {
      await beforeWrite?.(outputBytes + final.byteLength, final.byteLength);
      signal?.throwIfAborted();
      await writeAll(output, final);
      outputBytes += final.byteLength;
    }
    await output.close();
    outputOpen = false;
    return { path: targetPath, size: outputBytes };
  } catch (error) {
    if (reader && !readerDone) {
      await reader.cancel(error).catch(() => undefined);
    } else if (!reader) {
      await response.body.cancel(error).catch(() => undefined);
    }
    if (outputOpen) await output?.close().catch(() => undefined);
    if (targetCreated) await rm(targetPath, { force: true }).catch(() => undefined);
    throw error;
  } finally {
    try {
      reader?.releaseLock();
    } catch {
      // The stream may already have released its reader while propagating an abort.
    }
  }
}

export class LineObs {
  client: BaseClient;
  // リージョン別エンドポイント（JP アカウントは obs-jp。アルバム(GID)付与はリージョン側で行われる）
  prefix = process.env.VYLINE_OBS_PREFIX ?? "https://obs-jp.line-apps.com/";
  constructor(client: BaseClient) {
    this.client = client;
  }

  /**
   * Gets a message image URI by appending the given message ID to the prefixSticker
   * @param {string} [messageId] - The message ID to use in the URLSticker
   * @param {boolean} [isPreview=false] - Whether to append '/preview' to the URL.
   * @return {string} The getted message image
   */
  public getMessageDataUrl(
    messageId: string,
    isPreview: boolean = false,
    square: boolean = false,
  ): string {
    return `${this.prefix}r/${square ? "g2" : "talk"}/m/${messageId}${isPreview ? "/preview" : ""}`;
  }

  /**
   * Gets a message image URI by appending the given message ID to the prefixSticker
   * @param {string} [messageId] - The message ID to use in the URLSticker
   * @return {string} The getted message image
   */
  public getMessageMetadataUrl(messageId: string, square: boolean = false): string {
    return `${this.prefix}r/${square ? "g2" : "talk"}/m/${messageId}/object_info.obs`;
  }

  /**
   * @description Gets the message's data from LINE Obs.
   */
  public async downloadMessageData(options: {
    messageId: string;
    isPreview?: boolean;
    isSquare?: boolean;
  }): Promise<File> {
    if (!this.client.authToken) {
      throw new InternalError("Not setup yet", "Please call 'login()' first");
    }
    const { messageId, isPreview, isSquare } = {
      isPreview: false,
      isSquare: false,
      ...options,
    };
    const blob = await (
      await this.client.fetch(this.getMessageDataUrl(messageId, isPreview, isSquare), {
        headers: {
          accept: "application/json, text/plain, */*",
          "x-line-application": this.client.request.systemType,
          "x-Line-access": this.client.authToken,
        },
      })
    ).blob();
    const fileInfo = await this.getMessageObsMetadata({
      messageId,
      isSquare,
    });
    return new File([blob], fileInfo.name, { type: blob.type });
  }

  /**
   * @description Gets the message's data from LINE Obs.
   */
  public async getMessageObsMetadata(options: {
    messageId: string;
    isSquare?: boolean;
  }): Promise<ObsMetadata> {
    if (!this.client.authToken) {
      throw new InternalError("Not setup yet", "Please call 'login()' first");
    }
    const { messageId, isSquare } = {
      isSquare: false,
      ...options,
    };
    const r = await this.client.fetch(this.getMessageMetadataUrl(messageId, isSquare), {
      headers: {
        accept: "application/json, text/plain, */*",
        "x-line-application": this.client.request.systemType,
        "x-Line-access": this.client.authToken,
      },
    });
    return r.json();
  }

  /**
   * @description Upload obs message to talk.
   */
  public async uploadObjTalk(
    to: string,
    type: ObjType,
    data: Blob,
    oid?: string,
    filename?: string,
    durationMs?: number,
    reqseqOverride?: number,
    signal?: AbortSignal,
  ): Promise<{
    objId: string;
    objHash: string;
    headers: Headers;
  }> {
    if (!this.client.authToken) {
      throw new InternalError("Not setup yet", "Please call 'login()' first");
    }
    const ext = MimeType[data.type as keyof typeof MimeType];
    const reqseqValue = oid ? undefined : (reqseqOverride ?? (await this.client.getReqseq("talk")));
    const param: {
      oid: string;
      reqseq?: string;
      tomid?: string;
      ver: string;
      name: string;
      type: string;
      cat?: string;
      duration?: string;
    } = {
      ver: "2.0",
      name: filename || "vyline." + ext,
      type,
      ...(oid
        ? { oid: oid }
        : {
            oid: "reqseq",
            tomid: to,
            reqseq: reqseqValue.toString(),
          }),
    };
    if (type === "image") {
      param.cat = "original";
    } else if (type === "gif") {
      param.cat = "original";
      param.type = "image";
    } else if (type === "audio" || type === "video") {
      // LINE uses this obs param verbatim as the displayed length (it does not
      // recompute it from the uploaded file), so a caller-supplied real duration
      // must be honoured; keep the historical value as the fallback.
      param.duration = (durationMs ?? 1919).toString();
    }
    const toType: "talk" | "g2" = to[0] === "m" || to[0] === "t" ? "g2" : "talk";
    return await this.uploadObjectForService({
      data,
      oType: type,
      obsPath: `${toType}/m/${oid ?? "reqseq"}`,
      filename: param.name,
      params: param,
      signal,
    });
  }

  public async uploadObjTalkBatch(
    to: string,
    items: Array<{
      type: ObjType;
      data: Blob;
      filename?: string;
      durationMs?: number;
    }>,
    signal?: AbortSignal,
  ): Promise<Array<{ objId: string; objHash: string; headers: Headers } | { error: unknown }>> {
    if (!items.length) return [];
    const reqseqs = await this.client.getReqseqs("talk", items.length);
    // 順次アップロード。失敗は結果に記録し、成功済み分を保持する
    //（Promise.all だと 1 失敗で全体が throw され、部分成功が分からなくなる）
    const out: Array<{ objId: string; objHash: string; headers: Headers } | { error: unknown }> = [];
    for (let index = 0; index < items.length; index++) {
      signal?.throwIfAborted();
      const item = items[index]!;
      try {
        out.push(
          await this.uploadObjTalk(
            to,
            item.type,
            item.data,
            undefined,
            item.filename,
            item.durationMs,
            reqseqs[index],
            signal,
          ),
        );
      } catch (error) {
        out.push({ error });
      }
    }
    return out;
  }

  public async uploadObjTalkMessage(options: {
    to: string;
    type: ObjType;
    data: Blob;
    filename?: string;
    durationMs?: number;
    relatedMessageId?: string;
    messageRelationType?: "FORWARD" | "AUTO_REPLY" | "SUBORDINATE" | "REPLY";
  }): Promise<Message> {
    const {
      to,
      type,
      data,
      filename,
      durationMs,
      relatedMessageId,
      messageRelationType,
    } = options;
    const ext = MimeType[data.type as keyof typeof MimeType];
    const typeSet: {
      image: [string, 1];
      video: [string, 2];
      audio: [string, 3];
      file: [string, 14];
      gif: [string, 1];
    } = {
      image: ["emi", 1],
      video: ["emv", 2],
      audio: ["ema", 3],
      file: ["emf", 14],
      gif: ["emi", 1],
    };
    const [obsNamespace, contentType] = typeSet[type];
    const params: Record<string, string> = { type: "file" };
    if (type === "image" || type === "gif") {
      params["cat"] = "original";
    }
    if (type === "gif") {
      params["type"] = "image";
    }
    if (type === "audio" || type === "video") {
      params["duration"] = (durationMs ?? 1919).toString();
    }
    const toType: "talk" | "g2" = to[0] === "m" || to[0] === "t" ? "g2" : "talk";
    const oid = crypto.randomUUID();
    const { objId } = await this.uploadObjectForService({
      data,
      oType: type,
      obsPath: `${toType}/m/${oid}`,
      params: {
        ...params,
        ver: "2.0",
        name: filename || `vyline.${ext}`,
      },
    });

    return await this.client.talk.sendMessage({
      to,
      contentType,
      contentMetadata: {
        SID: obsNamespace,
        OID: objId,
        FILE_SIZE: data.size.toString(),
        fileName: filename || `line.${ext}`,
        ...(type === "image" || type === "gif" || type === "video"
          ? {
              MEDIA_CONTENT_INFO: JSON.stringify({
                category: "original",
                fileSize: data.size,
                extension: ext,
                animated: type === "gif",
              }),
            }
          : {}),
      },
      relatedMessageId,
      messageRelationType: relatedMessageId ? messageRelationType : undefined,
    });
  }

  async uploadObjectForService(options: {
    data: Blob;
    oType?: ObjType;
    obsPath?: string;
    params?: Record<string, string | undefined>;
    filename?: string;
    addHeaders?: Record<string, string>;
    signal?: AbortSignal;
  }): Promise<{ objId: string; objHash: string; headers: Headers }> {
    this.client.log("Obs.uploadObjectForService", options);
    let { data, oType, obsPath, params, filename, addHeaders, signal } = {
      oType: "image",
      obsPath: "myhome/h",
      ...options,
    };
    const obsPathFinal = `/r/${obsPath}`;
    oType = oType.toLowerCase();

    filename = filename || crypto.randomUUID();
    const baseParams = {
      type: oType,
      ver: "2.0",
      name: filename,
    };

    params = { ...baseParams, ...(params || {}) };

    if (!data || data.size === 0) {
      throw new InternalError("ObsError", "No data to send.");
    }
    let headers: Record<string, string> = this.client.request.getHeader("POST");
    headers["content-type"] = "application/octet-stream";
    headers["X-Obs-Params"] = Buffer.from(JSON.stringify(params)).toString("base64");

    if (addHeaders) {
      headers = { ...headers, ...addHeaders };
    }

    const response = await this.client.fetch(this.prefix + obsPathFinal, {
      method: "POST",
      headers,
      body: data,
      signal,
    });

    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new InternalError(
        "ObsError",
        `upload failed: HTTP ${response.status} ${response.statusText}`,
      );
    }

    const objId = response.headers.get("x-obs-oid") ?? "";
    const objHash = response.headers.get("x-obs-hash") ?? "";
    if (!objId) {
      await response.body?.cancel().catch(() => undefined);
      throw new InternalError("ObsError", "upload response did not include x-obs-oid");
    }
    this.client.log("Obs.uploadObjectForServiceResponse", {
      objId,
      objHash,
      headers: response.headers.toString(),
    });

    return { objId, objHash, headers: response.headers };
  }

  async downloadObjectResponseForService(options: {
    obsPath: string;
    oid: string;
    addHeaders?: Record<string, string>;
    signal?: AbortSignal;
  }): Promise<Response> {
    let { obsPath, oid, addHeaders, signal } = {
      addHeaders: {},
      ...options,
    };
    if (obsPath.includes("{oid}")) {
      obsPath = obsPath.replace("{oid}", oid);
    } else {
      obsPath += "/" + oid;
    }
    let headers: Record<string, string> = this.client.request.getHeader("GET");
    headers = { ...headers, ...addHeaders };

    const obsPathFinal = "r/" + obsPath;
    return await this.client.fetch(this.prefix + obsPathFinal, {
      method: "GET",
      headers,
      signal,
    });
  }

  async downloadObjectForService(options: {
    obsPath: string;
    oid: string;
    addHeaders?: Record<string, string>;
  }): Promise<Blob> {
    return (await this.downloadObjectResponseForService(options)).blob();
  }

  public async uploadMediaByE2EE(options: {
    data: Blob;
    oType: ObjType;
    to: string;
    filename?: string;
    /** Optional thumbnail; encrypted with the same keyMaterial. #103. */
    preview?: Blob;
    relatedMessageId?: string;
    messageRelationType?: "FORWARD" | "AUTO_REPLY" | "SUBORDINATE" | "REPLY";
  }): Promise<Message> {
    const { data, oType, to, filename, preview, relatedMessageId, messageRelationType } = options;
    const typeSet: {
      image: [string, 1];
      video: [string, 2];
      audio: [string, 3];
      file: [string, 14];
      gif: [string, 1];
    } = {
      image: ["emi", 1],
      video: ["emv", 2],
      audio: ["ema", 3],
      file: ["emf", 14],
      gif: ["emi", 1],
    };

    const ext = (filename && filename.split(".").at(-1)) || MimeType[data.type];

    const serviceName = "talk";
    const [obsNamespace, contentType] = typeSet[oType];
    const params: Record<string, string> = { type: "file" };

    if (oType === "gif") {
      params["cat"] = "original";
    }
    if (!(to[0] === "u" || to[0] === "c")) {
      throw new InternalError("ObsError", "Invalid mid");
    }
    const rawData = Buffer.from(await data.arrayBuffer());
    const { keyMaterial, encryptedData } = await this.client.e2ee.encryptByKeyMaterial(rawData);
    const tempId = "reqid-" + crypto.randomUUID();
    // @ts-expect-error: will fix cuz typescript version change
    const edata = new Blob([encryptedData]);
    const { objId } = await this.uploadObjectForService({
      data: edata,
      oType: "file",
      obsPath: `${serviceName}/${obsNamespace}/${tempId}`,
      params,
    });
    if (oType === "image" || oType === "gif" || oType === "video") {
      let previewEdata: Blob;
      if (preview) {
        const enc = await this.client.e2ee.encryptByKeyMaterial(
          Buffer.from(await preview.arrayBuffer()),
          Buffer.from(keyMaterial, "base64"),
        );
        // @ts-expect-error: Buffer is a valid BlobPart at runtime
        previewEdata = new Blob([enc.encryptedData]);
      } else {
        previewEdata = edata;
      }
      const { objId: objId2, headers } = await this.uploadObjectForService({
        data: previewEdata,
        oType: "file",
        obsPath: `${serviceName}/${obsNamespace}/${objId}__ud-preview`,
        params,
      });
      if (objId !== objId2) {
        throw new InternalError(
          "ObsError",
          "objId not match: " + JSON.stringify(Object.fromEntries(headers)),
          {
            headers: Object.fromEntries(headers),
          },
        );
      }
    }

    // E2EE メディアは E2EE チャンクを作る。peer が E2EE 非対応の場合は plain として送る
    // （データ自体は keyMaterial で暗号化済み。keyMaterial を metadata に載せるため、
    //  受信側が metadata の鍵から復号できる）
    let chunks: string[] | Buffer[];
    let e2ee = true;
    try {
      chunks = await this.client.e2ee.encryptE2EEMessage(
        to,
        { keyMaterial, fileName: filename || "line." + ext },
        contentType,
      );
    } catch (e) {
      if (
        e instanceof Error &&
        (e.name === "Not support E2EE" ||
          e.message?.startsWith("Not support E2EE") ||
          e.message.includes("E2EE_RETRY_PLAIN") ||
          e.message.includes("member settings off"))
      ) {
        e2ee = false;
        chunks = [];
      } else {
        throw e;
      }
    }

    return await this.client.talk.sendMessage({
      to,
      chunks,
      contentType: contentType,
      e2ee,
      contentMetadata: {
        SID: obsNamespace,
        OID: objId,
        FILE_SIZE: edata.size.toString(),
        keyMaterial,
        fileName: filename || `line.${ext}`,
        ...(e2ee ? { e2eeVersion: "2" } : {}),
        ...(oType === "image" || oType === "gif" || oType === "video"
          ? {
              MEDIA_CONTENT_INFO: JSON.stringify({
                category: "original",
                fileSize: edata.size,
                extension: ext,
                animated: oType == "gif",
              }),
            }
          : {}),
      },
      relatedMessageId,
      messageRelationType: relatedMessageId ? messageRelationType : undefined,
    });
  }

  /**
   * File-backed E2EE upload for large media. Encryption is written beside the
   * staged source and OBS receives a file-backed Blob, so neither plaintext nor
   * ciphertext scales the JavaScript heap.
   */
  public async uploadMediaByE2EEFromFile(options: {
    dataPath: string;
    size: number;
    mimeType: string;
    oType: ObjType;
    to: string;
    filename?: string;
    previewPath?: string;
    previewSize?: number;
    relatedMessageId?: string;
    messageRelationType?: "FORWARD" | "AUTO_REPLY" | "SUBORDINATE" | "REPLY";
    maxBytes?: number;
    signal?: AbortSignal;
  }): Promise<Message> {
    const {
      dataPath,
      size,
      mimeType,
      oType,
      to,
      filename,
      previewPath,
      previewSize,
      relatedMessageId,
      messageRelationType,
      maxBytes = DEFAULT_MAX_E2EE_MEDIA_BYTES,
      signal,
    } = options;
    assertMediaByteLimit(maxBytes);
    signal?.throwIfAborted();
    const sourceInfo = await stat(dataPath);
    if (!sourceInfo.isFile() || sourceInfo.size !== size || size <= 0 || size > maxBytes) {
      throw new Error("staged media size changed before E2EE upload");
    }
    if (!(to[0] === "u" || to[0] === "c")) {
      throw new InternalError("ObsError", "Invalid mid");
    }

    const typeSet: Record<ObjType, [string, ContentType]> = {
      image: ["emi", 1],
      video: ["emv", 2],
      audio: ["ema", 3],
      file: ["emf", 14],
      gif: ["emi", 1],
    };
    const [obsNamespace, contentType] = typeSet[oType];
    const params: Record<string, string> = { type: "file" };
    if (oType === "gif") params["cat"] = "original";
    const ext =
      (filename && filename.split(".").at(-1)) ||
      MimeType[mimeType as keyof typeof MimeType] ||
      "bin";
    const keyMaterialBytes = crypto.randomBytes(32);
    const keyMaterial = keyMaterialBytes.toString("base64");
    let chunks: string[] | Buffer[];
    try {
      chunks = await this.client.e2ee.encryptE2EEMessage(
        to,
        { keyMaterial, fileName: filename || `line.${ext}` },
        contentType,
      );
    } catch (error) {
      if (
        error instanceof Error &&
        (error.name === "Not support E2EE" ||
          error.message.startsWith("Not support E2EE") ||
          error.message.includes("E2EE_RETRY_PLAIN") ||
          error.message.includes("member settings off"))
      ) {
        throw new Error("E2EE_RETRY_PLAIN: media peer does not support E2EE", {
          cause: error,
        });
      }
      throw error;
    }
    signal?.throwIfAborted();
    const keys = await this.client.e2ee.deriveKeyMaterial(keyMaterialBytes);
    const encryptedPath = `${dataPath}.${crypto.randomUUID()}.e2ee-partial`;
    const encryptedPreviewPath = `${dataPath}.${crypto.randomUUID()}.e2ee-preview-partial`;

    try {
      const encrypted = await encryptE2eeMediaFile(
        dataPath,
        encryptedPath,
        keys,
        maxBytes,
        signal,
      );
      const encryptedBody = await openAsBlob(encrypted.path, {
        type: "application/octet-stream",
      });
      const tempId = `reqid-${crypto.randomUUID()}`;
      const { objId } = await this.uploadObjectForService({
        data: encryptedBody,
        oType: "file",
        obsPath: `talk/${obsNamespace}/${tempId}`,
        params,
        signal,
      });

      if (oType === "image" || oType === "gif" || oType === "video") {
        let previewBody: Blob = encryptedBody;
        if (previewPath) {
          const preview = await stat(previewPath);
          if (
            !preview.isFile() ||
            preview.size <= 0 ||
            preview.size !== previewSize ||
            preview.size > Math.min(maxBytes, size)
          ) {
            throw new Error("staged media preview size changed before E2EE upload");
          }
          const encryptedPreview = await encryptE2eeMediaFile(
            previewPath,
            encryptedPreviewPath,
            keys,
            maxBytes,
            signal,
          );
          previewBody = await openAsBlob(encryptedPreview.path, {
            type: "application/octet-stream",
          });
        }
        const { objId: previewObjId, headers } = await this.uploadObjectForService({
          data: previewBody,
          oType: "file",
          obsPath: `talk/${obsNamespace}/${objId}__ud-preview`,
          params,
          signal,
        });
        if (objId !== previewObjId) {
          throw new InternalError(
            "ObsError",
            `objId not match: ${JSON.stringify(Object.fromEntries(headers))}`,
            { headers: Object.fromEntries(headers) },
          );
        }
      }

      signal?.throwIfAborted();
      return await this.client.talk.sendMessage({
        to,
        chunks,
        contentType,
        e2ee: true,
        contentMetadata: {
          SID: obsNamespace,
          OID: objId,
          FILE_SIZE: encrypted.size.toString(),
          keyMaterial,
          fileName: filename || `line.${ext}`,
          e2eeVersion: "2",
          ...(oType === "image" || oType === "gif" || oType === "video"
            ? {
                MEDIA_CONTENT_INFO: JSON.stringify({
                  category: "original",
                  fileSize: encrypted.size,
                  extension: ext,
                  animated: oType === "gif",
                }),
              }
            : {}),
        },
        relatedMessageId,
        messageRelationType: relatedMessageId ? messageRelationType : undefined,
      });
    } finally {
      await Promise.allSettled([
        rm(encryptedPath, { force: true }),
        rm(encryptedPreviewPath, { force: true }),
      ]);
    }
  }

  private async prepareE2eeMediaDownload(message: Message): Promise<{
    oid: string;
    obsPath: string;
    talkMeta: string;
    keyMaterial: string;
    fileName: string;
  } | null> {
    if (!(message.to[0] === "u" || message.to[0] === "c")) {
      throw new InternalError("ObsError", "Invalid mid");
    }
    const { id } = message;
    const contentMetadata = message.contentMetadata ?? {};
    const meta = (contentMetadata ?? {}) as Record<string, unknown>;
    // Desktop 準拠: メディア鍵は contentMetadata.keyMaterial に平文で載ることが多い
    // （自送信メッセージは chunks を持たないため、平文 key があればそれを使う）
    let keyMaterial: string;
    let fileName: string;
    const plainKey = typeof meta.keyMaterial === "string" && meta.keyMaterial;
    if (plainKey) {
      keyMaterial = plainKey;
      fileName = typeof meta.fileName === "string" ? meta.fileName : "media";
    } else {
      const chunks = message.chunks ?? [];
      if (!chunks.length) return null;
      const dec = await this.client.e2ee.decryptE2EEDataMessage(message);
      keyMaterial = String(dec.keyMaterial ?? "");
      fileName = String(dec.fileName ?? "media");
    }
    if (!keyMaterial) throw new Error("E2EE media key material is missing");
    const oid = typeof contentMetadata.OID === "string" ? contentMetadata.OID : "";
    const sid = typeof contentMetadata.SID === "string" ? contentMetadata.SID : "";
    if (!oid || !sid) throw new Error("E2EE media object metadata is missing");
    const talkMeta = Buffer.from(
      JSON.stringify({
        message: Buffer.from(
          writeStruct(
            [
              [11, 4, id],
              [15, 27, [12, []]],
            ],
            thrift.TBinaryProtocol,
          ),
        ).toString("base64"),
      }),
    ).toString("base64");
    return { oid, obsPath: `talk/${sid}`, talkMeta, keyMaterial, fileName };
  }

  public async downloadMediaByE2EEToFile(
    message: Message,
    targetPath: string,
    maxBytes = DEFAULT_MAX_E2EE_MEDIA_BYTES,
    signal?: AbortSignal,
    beforeWrite?: E2eeMediaBeforeWrite,
  ): Promise<DownloadedE2eeMediaFile | null> {
    assertMediaByteLimit(maxBytes);
    signal?.throwIfAborted();
    const context = await this.prepareE2eeMediaDownload(message);
    if (!context) return null;
    const keyMaterial = Buffer.from(context.keyMaterial, "base64");
    if (keyMaterial.byteLength !== 32) {
      throw new Error("E2EE media key material must decode to exactly 32 bytes");
    }
    const keys = await this.client.e2ee.deriveKeyMaterial(keyMaterial);
    signal?.throwIfAborted();
    const response = await this.downloadObjectResponseForService({
      oid: context.oid,
      obsPath: context.obsPath,
      addHeaders: { "X-Talk-Meta": context.talkMeta },
      signal,
    });
    try {
      const result = await decryptE2eeMediaResponseToFile(
        response,
        targetPath,
        keys,
        maxBytes,
        signal,
        beforeWrite,
      );
      return {
        ...result,
        fileName: context.fileName,
        contentType: response.headers.get("content-type") ?? "application/octet-stream",
      };
    } catch (error) {
      await response.body?.cancel(error).catch(() => undefined);
      throw error;
    }
  }

  public async downloadMediaByE2EE(message: Message): Promise<File | null> {
    const context = await this.prepareE2eeMediaDownload(message);
    if (!context) return null;
    const data = await this.downloadObjectForService({
      oid: context.oid,
      obsPath: context.obsPath,
      addHeaders: { "X-Talk-Meta": context.talkMeta },
    });
    const fileData = new File(
      [
        (await this.client.e2ee.decryptByKeyMaterial(
          Buffer.from(await data.arrayBuffer()),
          context.keyMaterial,
        )) as unknown as BlobPart,
      ],
      context.fileName,
      { type: data.type },
    );
    return fileData;
  }
}
