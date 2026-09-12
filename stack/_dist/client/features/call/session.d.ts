import type { Client } from "../../mod.ts";
import type * as LINETypes from "@vyline/line-types";
import type { AudioSink, AudioSource, CodecFactory, PcmFrame } from "./audio.js";
import { TypedEventEmitter } from "../../../base/core/typed-event-emitter/index.js";
import type { EncodedVideoFrame } from "./planet/evs3.js";
import { type CallAudioPacket } from "./groupAudio.js";
import type { ConferenceMember } from "./planet/conference.js";
export type CallSessionState = "idle" | "acquiring" | "connecting" | "ringing" | "in-call" | "ending" | "ended" | "failed";
export type CallKind = "AUDIO" | "VIDEO" | "FACEPLAY";
export interface CallSessionOpts {
    to: string;
    kind?: CallKind;
    direction?: "outgoing" | "incoming";
    fromEnvInfo?: Record<string, string>;
    codecs?: CodecFactory;
    transport?: CallTransport;
    /** transport 選択のため事前 acquire した route（二重 acquire 回避） */
    preacquiredRoute?: LINETypes.CallRoute;
    group?: {
        route: LINETypes.GroupCallRoute;
    };
}
export interface CallAudioProfile {
    frameDurationMs?: number;
    bitrate?: number;
    bandwidth?: "narrowband" | "mediumband" | "wideband" | "superwideband" | "fullband";
    signal?: "auto" | "voice" | "music";
    vbr?: boolean;
}
export interface CallTransport {
    readonly audioProfile?: CallAudioProfile | undefined;
    connect(opts: {
        route: LINETypes.CallRoute | LINETypes.GroupCallRoute;
        kind?: CallKind;
    }): Promise<void>;
    readonly videoAvailable?: boolean;
    onVideoState?: (enabled: boolean) => void;
    onConference?: (members: ConferenceMember[]) => void;
    setVideoEnabled?(enabled: boolean): Promise<void>;
    sendVideo?(frame: EncodedVideoFrame): Promise<void>;
    receiveVideo?(): AsyncIterable<EncodedVideoFrame>;
    close(): Promise<void>;
    send(packet: Uint8Array, options?: {
        audioLevel?: number;
    }): void | Promise<void>;
    receive(): AsyncIterable<Uint8Array>;
    receiveAudio?(): AsyncIterable<CallAudioPacket>;
    joinGroup?(opts: {
        roomId: string;
    }): Promise<unknown>;
    /** Optional. When present, CallSession.start() drives the full
     *  signaling dialog after connect() (SIP INVITE → 200 → ACK). */
    invite?(opts: {
        to: string;
    }): Promise<unknown>;
    /** Optional. Incoming-call transports complete their callee-side signaling
     *  after connect() using the route delivered by NOTIFIED_RECEIVED_CALL. */
    answer?(): Promise<unknown>;
    /** Optional. PLANET-style transports may enter ringing after INVITE and
     *  only become media-ready after the peer sends CONN_REQ. */
    waitForAnswer?(opts?: {
        to: string;
    }): Promise<unknown>;
}
export declare const stubTransport: CallTransport;
export type CallSessionEvents = {
    state: (newState: CallSessionState, prev: CallSessionState) => void;
    connected: (route: LINETypes.CallRoute | LINETypes.GroupCallRoute) => void;
    ended: (reason: string) => void;
    error: (err: Error) => void;
    video: (state: CallVideoState) => void;
    participants: (members: ConferenceMember[]) => void;
};
export interface CallVideoState {
    available: boolean;
    localEnabled: boolean;
    remoteEnabled: boolean;
}
export declare class CallSession extends TypedEventEmitter<CallSessionEvents> {
    #private;
    constructor(client: Client, opts: CallSessionOpts);
    get state(): CallSessionState;
    get participants(): ConferenceMember[] | undefined;
    get route(): LINETypes.CallRoute | LINETypes.GroupCallRoute | undefined;
    get peer(): string;
    get kind(): CallKind;
    get videoState(): CallVideoState;
    setVideoEnabled(enabled: boolean): Promise<void>;
    sendVideo(frame: EncodedVideoFrame): Promise<void>;
    receivedVideo(): AsyncIterable<EncodedVideoFrame>;
    start(): Promise<LINETypes.CallRoute | LINETypes.GroupCallRoute>;
    sendStream(source: AudioSource, opts?: {
        signal?: AbortSignal;
    }): Promise<void>;
    sendBuffer(opts: {
        samples: Int16Array;
        sampleRate: number;
        channels?: number;
    }): Promise<void>;
    sendFile(opts: {
        bytes: Uint8Array;
        decode: (b: Uint8Array) => Promise<{
            samples: Int16Array;
            sampleRate: number;
            channels: number;
        }> | {
            samples: Int16Array;
            sampleRate: number;
            channels: number;
        };
    }): Promise<void>;
    receiveInto(sink: AudioSink): Promise<void>;
    received(): AsyncGenerator<PcmFrame>;
    end(reason?: string): Promise<void>;
}
