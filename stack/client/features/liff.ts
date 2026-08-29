// High-level LIFF adapter on top of base/service/liff/mod.ts.
import type { Client } from "../mod.ts";

export type LiffMessage =
  | LiffTextMessage
  | LiffStickerMessage
  | LiffImageMessage
  | LiffFlexMessage
  | LiffTemplateMessage
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  | Record<string, any>;

export interface LiffTextMessage {
  type: "text";
  text: string;
  sentBy?: { label: string; iconUrl: string; linkUrl?: string };
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

export function text(body: string, sentBy?: LiffTextMessage["sentBy"]): LiffTextMessage {
  return sentBy ? { type: "text", text: body, sentBy } : { type: "text", text: body };
}

export function sticker(packageId: string, stickerId: string): LiffStickerMessage {
  return { type: "sticker", packageId, stickerId };
}

export function image(
  originalContentUrl: string,
  previewImageUrl: string = originalContentUrl,
): LiffImageMessage {
  return { type: "image", originalContentUrl, previewImageUrl };
}

export function flex(altText: string, contents: Record<string, unknown>): LiffFlexMessage {
  return { type: "flex", altText, contents };
}

/** Attach the user-facing sender metadata without mutating the original message. */
export function withSender<T extends LiffMessage>(
  message: T,
  sender: LiffSender,
): LiffMessageWithSender<T> {
  return { ...message, sender };
}

/** Backward-compatible helper for attaching display attribution. */
export function withAttribution<T extends LiffMessage>(
  message: T,
  attribution: LiffAttribution,
): LiffMessageWithAttribution<T> {
  return {
    ...message,
    sender: {
      name: attribution.name,
      ...(attribution.iconUrl ? { iconUrl: attribution.iconUrl } : {}),
      ...(attribution.linkUrl ? { linkUrl: attribution.linkUrl } : {}),
    },
  };
}

export function prepareSendMessage(message: LiffSendMessage): LiffMessage {
  if (!message.sender) return message;
  const { sender, ...base } = message;
  return {
    ...base,
    sentBy: {
      label: sender.name,
      iconUrl: sender.iconUrl ?? "",
      ...(sender.linkUrl ? { linkUrl: sender.linkUrl } : {}),
    },
  };
}
export interface LiffClient {
  readonly defaultLiffId: string;
  setDefaultLiffId(liffId: string): void;
  getToken(opts: { chatMid?: string; liffId?: string; lang?: string }): Promise<string>;
  issueView(opts: {
    chatMid?: string;
    liffId?: string;
    lang?: string;
  }): Promise<import("@vyline/line-types").LiffViewResponse>;
  issueSubView(
    ...args: Parameters<import("../../base/service/liff/mod.ts").LiffService["issueSubLiffView"]>
  ): ReturnType<import("../../base/service/liff/mod.ts").LiffService["issueSubLiffView"]>;
  shareMessages(
    to: string,
    messages: LiffSendMessage[],
    opts?: LiffSendOptions,
  ): Promise<unknown>;
  shareMessage(
    to: string,
    message: LiffSendMessage,
    opts?: LiffSendOptions,
  ): Promise<unknown>;
  sendLiff(to: string, message: LiffSendMessage, opts?: LiffSendOptions): Promise<unknown>;
  readonly service: import("../../base/service/liff/mod.ts").LiffService;
}

class ClientLiff implements LiffClient {
  #client: Client;
  #liffId: string;
  constructor(client: Client) {
    this.#client = client;
    this.#liffId = client.base.liff.liffId;
  }
  get defaultLiffId(): string {
    return this.#liffId;
  }
  setDefaultLiffId(liffId: string): void {
    this.#liffId = liffId;
    this.#client.base.liff.liffId = liffId;
  }
  get service() {
    return this.#client.base.liff;
  }
  async getToken(opts: { chatMid?: string; liffId?: string; lang?: string }) {
    return await this.#client.base.liff.getLiffToken({
      chatMid: opts.chatMid,
      liffId: opts.liffId ?? this.#liffId,
      lang: opts.lang,
    });
  }
  issueView(opts: { chatMid?: string; liffId?: string; lang?: string }) {
    return this.#client.base.liff.issueLiffView({
      chatMid: opts.chatMid,
      liffId: opts.liffId ?? this.#liffId,
      lang: opts.lang,
    });
  }
  issueSubView(
    ...args: Parameters<typeof this.service.issueSubLiffView>
  ): ReturnType<typeof this.service.issueSubLiffView> {
    return this.service.issueSubLiffView(...args);
  }
  async shareMessages(
    to: string,
    messages: LiffSendMessage[],
    opts: LiffSendOptions = {},
  ) {
    const preparedMessages = messages.map(prepareSendMessage);
    return await this.#client.base.liff.sendLiff({
      to,
      messages: preparedMessages as never,
      liffId: opts.liffId,
      forceIssue: opts.forceIssue,
    });
  }
  shareMessage(to: string, message: LiffSendMessage, opts?: LiffSendOptions) {
    return this.shareMessages(to, [message], opts);
  }
  sendLiff(to: string, message: LiffSendMessage, opts?: LiffSendOptions) {
    return this.shareMessage(to, message, opts);
  }
}

export function createLiffClient(client: Client): LiffClient {
  return new ClientLiff(client);
}
