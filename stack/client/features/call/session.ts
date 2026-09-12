// CallSession — control plane is real, transport is pluggable.
import type { Client } from "../../mod.ts";
import type * as LINETypes from "@vyline/line-types";
import type {
  AudioDecoder,
  AudioEncoder,
  AudioSink,
  AudioSource,
  CodecFactory,
  PcmFrame,
} from "./audio.js";
import { defaultCodecFactory, pcmAudioLevel } from "./audio.js";
import { TypedEventEmitter } from "../../../base/core/typed-event-emitter/index.js";
import type { EncodedVideoFrame } from "./planet/evs3.js";
import { GroupAudioMixer, type CallAudioPacket } from "./groupAudio.js";
import type { ConferenceMember } from "./planet/conference.js";

export type CallSessionState =
  | "idle"
  | "acquiring"
  | "connecting"
  | "ringing"
  | "in-call"
  | "ending"
  | "ended"
  | "failed";

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
  group?: { route: LINETypes.GroupCallRoute };
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
  send(packet: Uint8Array, options?: { audioLevel?: number }): void | Promise<void>;
  receive(): AsyncIterable<Uint8Array>;
  receiveAudio?(): AsyncIterable<CallAudioPacket>;
  joinGroup?(opts: { roomId: string }): Promise<unknown>;
  /** Optional. When present, CallSession.start() drives the full
   *  signaling dialog after connect() (SIP INVITE → 200 → ACK). */
  invite?(opts: { to: string }): Promise<unknown>;
  /** Optional. Incoming-call transports complete their callee-side signaling
   *  after connect() using the route delivered by NOTIFIED_RECEIVED_CALL. */
  answer?(): Promise<unknown>;
  /** Optional. PLANET-style transports may enter ringing after INVITE and
   *  only become media-ready after the peer sends CONN_REQ. */
  waitForAnswer?(opts?: { to: string }): Promise<unknown>;
}

export const stubTransport: CallTransport = {
  connect() {
    throw new Error("CallTransport not configured");
  },
  close() {
    return Promise.resolve();
  },
  send() {
    throw new Error("stubTransport.send");
  },
  async *receive() {
    /* */
  },
};

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

export class CallSession extends TypedEventEmitter<CallSessionEvents> {
  #client: Client;
  #opts: CallSessionOpts;
  #state: CallSessionState = "idle";
  #route?: LINETypes.CallRoute | LINETypes.GroupCallRoute;
  #transport: CallTransport;
  #codecs: CodecFactory;
  #encoder?: AudioEncoder;
  #decoder?: AudioDecoder;
  #sendAbort?: AbortController;
  #receiveSink?: AudioSink;
  #endTask?: Promise<void>;
  #startTask?: Promise<LINETypes.CallRoute | LINETypes.GroupCallRoute>;
  #groupMixer?: GroupAudioMixer;
  #participants?: ConferenceMember[];
  #groupAudioSources = new Set<number>();
  #groupVideoReady = new Set<string>();
  #localVideoEnabled = false;
  #remoteVideoEnabled = false;
  #remoteVideoPaused = false;
  #remoteVideoNeedsKey = true;

  constructor(client: Client, opts: CallSessionOpts) {
    super();
    this.#client = client;
    this.#opts = opts;
    this.#transport = opts.transport ?? stubTransport;
    this.#codecs = opts.codecs ?? defaultCodecFactory;
    this.#transport.onConference = (members) => {
      if (
        !this.#opts.group ||
        this.#state === "ending" ||
        this.#state === "ended" ||
        this.#state === "failed"
      )
        return;
      const sources = new Set(
        members.flatMap((m) => m.sources.filter((s) => s.name === "A").map((s) => s.ssrc)),
      );
      for (const ssrc of this.#groupAudioSources)
        if (!sources.has(ssrc)) this.#groupMixer?.remove(ssrc);
      this.#groupAudioSources = sources;
      this.#participants = members.map((m) => ({
        ...m,
        sources: m.sources.map((s) => ({ ...s })),
      }));
      for (const mid of this.#groupVideoReady)
        if (!members.some((m) => m.mid === mid && m.sources.some((s) => s.name === "V")))
          this.#groupVideoReady.delete(mid);
      const videoEnabled = this.#groupVideoReady.size > 0;
      if (this.#remoteVideoEnabled !== videoEnabled) {
        this.#remoteVideoEnabled = videoEnabled;
        this.emit("video", this.videoState);
      }
      this.emit("participants", this.participants!);
    };
    this.#transport.onVideoState = (enabled) => {
      if (this.#opts.group) return; // Group pause/leave is scoped through conference sources.
      this.#remoteVideoPaused = !enabled;
      if (!enabled) this.#remoteVideoNeedsKey = true;
      this.#remoteVideoEnabled = enabled;
      this.emit("video", this.videoState);
    };
  }

  get state(): CallSessionState {
    return this.#state;
  }
  get participants(): ConferenceMember[] | undefined {
    return this.#participants?.map((m) => ({ ...m, sources: m.sources.map((s) => ({ ...s })) }));
  }
  get route(): LINETypes.CallRoute | LINETypes.GroupCallRoute | undefined {
    return this.#route;
  }
  get peer(): string {
    return this.#opts.to;
  }
  get kind(): CallKind {
    return this.#opts.kind ?? "AUDIO";
  }
  get videoState(): CallVideoState {
    return {
      available: this.#transport.videoAvailable ?? false,
      localEnabled: this.#localVideoEnabled,
      remoteEnabled: this.#remoteVideoEnabled,
    };
  }

  async setVideoEnabled(enabled: boolean): Promise<void> {
    if (this.#state !== "in-call") throw new Error("Video session not in-call");
    if (!this.#transport.setVideoEnabled)
      throw new Error("Video is not supported by this transport");
    await this.#transport.setVideoEnabled(enabled);
    if (this.#state !== "in-call") return;
    this.#localVideoEnabled = enabled;
    this.emit("video", this.videoState);
  }

  async sendVideo(frame: EncodedVideoFrame): Promise<void> {
    if (this.#state !== "in-call" || !this.#localVideoEnabled || !this.#transport.sendVideo) {
      throw new Error("Video is not enabled");
    }
    await this.#transport.sendVideo(frame);
  }

  async *receivedVideo(): AsyncIterable<EncodedVideoFrame> {
    if (this.#state !== "in-call" || !this.#transport.receiveVideo) return;
    for await (const frame of this.#transport.receiveVideo()) {
      if (this.#state !== "in-call") return;
      if (this.#opts.group) {
        const mid = frame.sourceMid;
        if (
          !mid ||
          !this.#participants?.some((m) => m.mid === mid && m.sources.some((s) => s.name === "V"))
        )
          continue;
        if (!this.#groupVideoReady.has(mid) && !frame.key) continue;
        this.#groupVideoReady.add(mid);
        if (!this.#remoteVideoEnabled) {
          this.#remoteVideoEnabled = true;
          this.emit("video", this.videoState);
        }
        yield frame;
        continue;
      }
      if (this.#remoteVideoPaused) continue;
      if (this.#remoteVideoNeedsKey && !frame.key) continue;
      this.#remoteVideoNeedsKey = false;
      if (!this.#remoteVideoEnabled) {
        this.#remoteVideoEnabled = true;
        this.emit("video", this.videoState);
      }
      yield frame;
    }
  }

  #setState(s: CallSessionState) {
    if (s === this.#state) return;
    const prev = this.#state;
    this.#state = s;
    this.emit("state", s, prev);
  }

  start(): Promise<LINETypes.CallRoute | LINETypes.GroupCallRoute> {
    return (this.#startTask ??= this.#start());
  }

  #assertStarting(): void {
    if (this.#state === "ending" || this.#state === "ended" || this.#state === "failed") {
      throw new Error("Call ended during signaling");
    }
  }

  async #start(): Promise<LINETypes.CallRoute | LINETypes.GroupCallRoute> {
    this.#setState("acquiring");
    try {
      this.#route =
        this.#opts.group?.route ??
        this.#opts.preacquiredRoute ??
        (await this.#client.call.acquireRoute({
          to: this.#opts.to,
          callType: this.#opts.kind ?? "AUDIO",
          fromEnvInfo: this.#opts.fromEnvInfo,
        }));
      this.#assertStarting();
      this.#setState("connecting");
      await this.#transport.connect({ route: this.#route, kind: this.kind });
      this.#assertStarting();
      if (this.#opts.group) {
        if (!this.#transport.joinGroup || !this.#transport.receiveAudio) {
          throw new Error("CallTransport does not support group calls");
        }
        await this.#transport.joinGroup({ roomId: this.#opts.to });
      } else if (this.#opts.direction === "incoming") {
        this.#setState("ringing");
        if (!this.#transport.answer) {
          throw new Error("CallTransport does not support incoming calls");
        }
        await this.#transport.answer();
      } else {
        if (this.#transport.invite) {
          await this.#transport.invite({ to: this.#opts.to });
        }
        if (this.#transport.waitForAnswer) {
          this.#setState("ringing");
          await this.#transport.waitForAnswer({ to: this.#opts.to });
        }
      }
      this.#assertStarting();
      this.#setState("in-call");
      this.emit("connected", this.#route);
      return this.#route;
    } catch (e) {
      try {
        await this.#transport.close();
      } catch {
        /* preserve the signaling error */
      }
      const err = e instanceof Error ? e : new Error(String(e));
      if (this.#state === "ending" || this.#state === "ended") throw err;
      this.#setState("failed");
      this.emit("error", err);
      throw err;
    }
  }

  async sendStream(source: AudioSource, opts: { signal?: AbortSignal } = {}): Promise<void> {
    if (this.#state !== "in-call") {
      throw new Error(`sendStream: session not in-call (state=${this.#state})`);
    }
    this.#sendAbort = new AbortController();
    const signal = opts.signal
      ? mergeSignals(opts.signal, this.#sendAbort.signal)
      : this.#sendAbort.signal;
    const audioProfile = this.#transport.audioProfile;
    const enc = (this.#encoder ??= this.#codecs.newEncoder({
      sampleRate: 48000,
      channels: 1,
      ...audioProfile,
    }));
    const targetFrameSamples = audioProfile?.frameDurationMs
      ? Math.floor((48000 * audioProfile.frameDurationMs) / 1000)
      : 0;
    let pending = new Int16Array(0);
    for await (const frame of source.frames({ signal })) {
      if (signal.aborted) break;
      if (targetFrameSamples <= 0 || frame.sampleRate !== 48000 || frame.channels !== 1) {
        const packet = enc.encode(frame);
        if (packet)
          await this.#transport.send(packet, { audioLevel: pcmAudioLevel(frame.samples) });
        continue;
      }

      const combined = new Int16Array(pending.length + frame.samples.length);
      combined.set(pending);
      combined.set(frame.samples, pending.length);
      let offset = 0;
      while (offset + targetFrameSamples <= combined.length) {
        const samples = combined.slice(offset, offset + targetFrameSamples);
        const packet = enc.encode({ samples, sampleRate: 48000, channels: 1 });
        if (packet) await this.#transport.send(packet, { audioLevel: pcmAudioLevel(samples) });
        offset += targetFrameSamples;
      }
      pending = combined.slice(offset);
    }
  }

  async sendBuffer(opts: {
    samples: Int16Array;
    sampleRate: number;
    channels?: number;
  }): Promise<void> {
    const { bufferSource } = await import("./audio.js");
    await this.sendStream(bufferSource(opts));
  }

  async sendFile(opts: {
    bytes: Uint8Array;
    decode: (b: Uint8Array) =>
      | Promise<{
          samples: Int16Array;
          sampleRate: number;
          channels: number;
        }>
      | { samples: Int16Array; sampleRate: number; channels: number };
  }): Promise<void> {
    const decoded = await opts.decode(opts.bytes);
    await this.sendBuffer(decoded);
  }

  async receiveInto(sink: AudioSink): Promise<void> {
    if (this.#state !== "in-call") {
      throw new Error(`receiveInto: session not in-call (state=${this.#state})`);
    }
    this.#receiveSink = sink;
    for await (const frame of this.received()) await sink.write(frame);
    await sink.end?.();
  }

  async *received(): AsyncGenerator<PcmFrame> {
    if (this.#state !== "in-call") {
      throw new Error(`received: session not in-call (state=${this.#state})`);
    }
    if (this.#opts.group) {
      yield* this.#receivedGroup();
      return;
    }
    const dec = (this.#decoder ??= this.#codecs.newDecoder({
      sampleRate: 48000,
      channels: 1,
    }));
    for await (const packet of this.#transport.receive()) {
      try {
        const frame = dec.decode(packet);
        if (frame) yield frame;
      } catch {
        // Keep receiving after an isolated malformed/unsupported media packet.
      }
    }
  }

  async *#receivedGroup(): AsyncGenerator<PcmFrame> {
    const mixer = (this.#groupMixer = new GroupAudioMixer(this.#codecs));
    let done = false;
    let error: unknown;
    const pump = (async () => {
      for await (const packet of this.#transport.receiveAudio!()) {
        if (this.#state !== "in-call") break;
        if (this.#participants && !this.#groupAudioSources.has(packet.ssrc)) continue;
        mixer.push(packet, performance.now());
      }
    })()
      .catch((e) => {
        error = e;
      })
      .finally(() => {
        done = true;
      });
    try {
      while (!done && this.#state === "in-call") {
        await new Promise<void>((resolve) =>
          setTimeout(resolve, Math.max(1, 20 - (performance.now() % 20))),
        );
        if (this.#state !== "in-call") break;
        const frame = mixer.read(performance.now());
        if (frame) yield frame;
      }
      if (error) throw error;
    } finally {
      mixer.close();
      if (this.#state === "in-call") await this.end("audio-receive-ended");
      await pump;
    }
  }

  end(reason = "user-ended"): Promise<void> {
    if (this.#endTask) return this.#endTask;
    if (this.#state === "ended" || this.#state === "failed" || this.#state === "idle") {
      return Promise.resolve();
    }
    this.#endTask = Promise.resolve().then(async () => {
      this.#setState("ending");
      this.#sendAbort?.abort();
      try {
        await this.#transport.close();
      } catch {
        /* */
      }
      this.#encoder?.close?.();
      this.#localVideoEnabled = false;
      this.#remoteVideoEnabled = false;
      this.#decoder?.close?.();
      this.#groupMixer?.close();
      this.#groupAudioSources.clear();
      this.#groupVideoReady.clear();
      if (this.#opts.group) {
        this.#participants = [];
        this.emit("participants", []);
      }
      await this.#receiveSink?.end?.();
      this.#setState("ended");
      this.emit("ended", reason);
    });
    return this.#endTask;
  }
}

function mergeSignals(a: AbortSignal, b: AbortSignal): AbortSignal {
  if (a.aborted) return a;
  if (b.aborted) return b;
  const c = new AbortController();
  const onA = () => c.abort(a.reason);
  const onB = () => c.abort(b.reason);
  a.addEventListener("abort", onA, { once: true });
  b.addEventListener("abort", onB, { once: true });
  return c.signal;
}
