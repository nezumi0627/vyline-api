import { Buffer } from "node:buffer";
import { type BaseClient } from "../core/mod.js";
import type { Message } from "@vyline/line-types";
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
export type E2eeMediaBeforeWrite = (nextTotalBytes: number, pendingBytes: number) => void | Promise<void>;
interface E2eeMediaKeys {
    encKey: Buffer;
    macKey: Buffer;
    nonce: Buffer;
}
/** Encrypt one media file with bounded buffers and append LINE's HMAC tag. */
export declare function encryptE2eeMediaFile(sourcePath: string, targetPath: string, keys: E2eeMediaKeys, maxBytes?: number, signal?: AbortSignal): Promise<E2eeMediaFileResult>;
/**
 * Authenticate and decrypt an OBS response into an unpublished file. Only the
 * final 32-byte tag and the current network chunk are retained in memory.
 */
export declare function decryptE2eeMediaResponseToFile(response: Response, targetPath: string, keys: E2eeMediaKeys, maxBytes?: number, signal?: AbortSignal, beforeWrite?: E2eeMediaBeforeWrite): Promise<E2eeMediaFileResult>;
export declare class LineObs {
    client: BaseClient;
    prefix: string;
    constructor(client: BaseClient);
    /**
     * Gets a message image URI by appending the given message ID to the prefixSticker
     * @param {string} [messageId] - The message ID to use in the URLSticker
     * @param {boolean} [isPreview=false] - Whether to append '/preview' to the URL.
     * @return {string} The getted message image
     */
    getMessageDataUrl(messageId: string, isPreview?: boolean, square?: boolean): string;
    /**
     * Gets a message image URI by appending the given message ID to the prefixSticker
     * @param {string} [messageId] - The message ID to use in the URLSticker
     * @return {string} The getted message image
     */
    getMessageMetadataUrl(messageId: string, square?: boolean): string;
    /**
     * @description Gets the message's data from LINE Obs.
     */
    downloadMessageData(options: {
        messageId: string;
        isPreview?: boolean;
        isSquare?: boolean;
    }): Promise<File>;
    /**
     * @description Gets the message's data from LINE Obs.
     */
    getMessageObsMetadata(options: {
        messageId: string;
        isSquare?: boolean;
    }): Promise<ObsMetadata>;
    /**
     * @description Upload obs message to talk.
     */
    uploadObjTalk(to: string, type: ObjType, data: Blob, oid?: string, filename?: string, durationMs?: number, reqseqOverride?: number, signal?: AbortSignal): Promise<{
        objId: string;
        objHash: string;
        headers: Headers;
    }>;
    uploadObjTalkBatch(to: string, items: Array<{
        type: ObjType;
        data: Blob;
        filename?: string;
        durationMs?: number;
    }>, signal?: AbortSignal): Promise<Array<{
        objId: string;
        objHash: string;
        headers: Headers;
    } | {
        error: unknown;
    }>>;
    uploadObjTalkMessage(options: {
        to: string;
        type: ObjType;
        data: Blob;
        filename?: string;
        durationMs?: number;
        relatedMessageId?: string;
        messageRelationType?: "FORWARD" | "AUTO_REPLY" | "SUBORDINATE" | "REPLY";
    }): Promise<Message>;
    uploadObjectForService(options: {
        data: Blob;
        oType?: ObjType;
        obsPath?: string;
        params?: Record<string, string | undefined>;
        filename?: string;
        addHeaders?: Record<string, string>;
        signal?: AbortSignal;
    }): Promise<{
        objId: string;
        objHash: string;
        headers: Headers;
    }>;
    downloadObjectResponseForService(options: {
        obsPath: string;
        oid: string;
        addHeaders?: Record<string, string>;
        signal?: AbortSignal;
    }): Promise<Response>;
    downloadObjectForService(options: {
        obsPath: string;
        oid: string;
        addHeaders?: Record<string, string>;
    }): Promise<Blob>;
    uploadMediaByE2EE(options: {
        data: Blob;
        oType: ObjType;
        to: string;
        filename?: string;
        /** Optional thumbnail; encrypted with the same keyMaterial. #103. */
        preview?: Blob;
        relatedMessageId?: string;
        messageRelationType?: "FORWARD" | "AUTO_REPLY" | "SUBORDINATE" | "REPLY";
    }): Promise<Message>;
    /**
     * File-backed E2EE upload for large media. Encryption is written beside the
     * staged source and OBS receives a file-backed Blob, so neither plaintext nor
     * ciphertext scales the JavaScript heap.
     */
    uploadMediaByE2EEFromFile(options: {
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
    }): Promise<Message>;
    private prepareE2eeMediaDownload;
    downloadMediaByE2EEToFile(message: Message, targetPath: string, maxBytes?: number, signal?: AbortSignal, beforeWrite?: E2eeMediaBeforeWrite): Promise<DownloadedE2eeMediaFile | null>;
    downloadMediaByE2EE(message: Message): Promise<File | null>;
}
export {};
