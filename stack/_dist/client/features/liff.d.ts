import type { Client } from "../mod.ts";
export type LiffMessage = LiffTextMessage | LiffStickerMessage | LiffImageMessage | LiffFlexMessage | LiffTemplateMessage | Record<string, any>;
export interface LiffTextMessage {
    type: "text";
    text: string;
    sentBy?: {
        label: string;
        iconUrl: string;
        linkUrl?: string;
    };
}
/** User-facing sender metadata. It is normalized to LINE's `sentBy` wire shape. */
export interface LiffSender {
    name: string;
    iconUrl?: string;
    linkUrl?: string;
}
export interface LiffAttribution {
    name: string;
    iconUrl?: string;
    linkUrl?: string;
}
export type LiffSendMessage = LiffMessage & {
    sender?: LiffAttribution;
};
export interface LiffSendOptions {
    liffId?: string;
    forceIssue?: boolean;
}
export type LiffMessageWithSender<T extends LiffMessage = LiffMessage> = T & {
    sender: LiffSender;
};
export type LiffMessageWithAttribution<T extends LiffMessage = LiffMessage> = T & {
    sender: LiffSender;
};
export interface LiffStickerMessage {
    type: "sticker";
    packageId: string;
    stickerId: string;
}
export interface LiffImageMessage {
    type: "image";
    originalContentUrl: string;
    previewImageUrl: string;
}
export interface LiffFlexMessage {
    type: "flex";
    altText: string;
    contents: Record<string, unknown>;
}
export interface LiffTemplateMessage {
    type: "template";
    altText: string;
    template: Record<string, unknown>;
}
export declare function text(body: string, sentBy?: LiffTextMessage["sentBy"]): LiffTextMessage;
export declare function sticker(packageId: string, stickerId: string): LiffStickerMessage;
export declare function image(originalContentUrl: string, previewImageUrl?: string): LiffImageMessage;
export declare function flex(altText: string, contents: Record<string, unknown>): LiffFlexMessage;
/** Attach the user-facing sender metadata without mutating the original message. */
export declare function withSender<T extends LiffMessage>(message: T, sender: LiffSender): LiffMessageWithSender<T>;
/** Backward-compatible helper for attaching display attribution. */
export declare function withAttribution<T extends LiffMessage>(message: T, attribution: LiffAttribution): LiffMessageWithAttribution<T>;
export declare function prepareSendMessage(message: LiffSendMessage): LiffMessage;
export interface LiffClient {
    readonly defaultLiffId: string;
    setDefaultLiffId(liffId: string): void;
    getToken(opts: {
        chatMid?: string;
        liffId?: string;
        lang?: string;
    }): Promise<string>;
    issueView(opts: {
        chatMid?: string;
        liffId?: string;
        lang?: string;
    }): Promise<import("@vyline/line-types").LiffViewResponse>;
    issueSubView(...args: Parameters<import("../../base/service/liff/mod.ts").LiffService["issueSubLiffView"]>): ReturnType<import("../../base/service/liff/mod.ts").LiffService["issueSubLiffView"]>;
    shareMessages(to: string, messages: LiffSendMessage[], opts?: LiffSendOptions): Promise<unknown>;
    shareMessage(to: string, message: LiffSendMessage, opts?: LiffSendOptions): Promise<unknown>;
    sendLiff(to: string, message: LiffSendMessage, opts?: LiffSendOptions): Promise<unknown>;
    readonly service: import("../../base/service/liff/mod.ts").LiffService;
}
export declare function createLiffClient(client: Client): LiffClient;
