import { assert, assertEquals, assertRejects } from "@vyline/protocol/stack/assert";
import { CallSession, type CallTransport } from "./session.ts";
import type { AudioDecoder, AudioEncoder, CodecFactory, PcmFrame } from "./audio.ts";
import { bufferSink, bufferSource } from "./audio.ts";

function fakeClient() {
  const acquired: unknown[] = [];
  const fakeRoute = {
    fromToken: "tok",
    callFlowType: "NEW",
    voipAddress: "1.2.3.4",
    voipUdpPort: 9000,
  };
  return {
    acquired,
    client: {
      call: {
        acquireRoute(opts: unknown) {
          acquired.push(opts);
          return Promise.resolve(fakeRoute);
        },
      },
    } as never,
    fakeRoute,
  };
}

function recordingTransport(): CallTransport & { sent: Uint8Array[]; closed: boolean } {
  const sent: Uint8Array[] = [];
  let closed = false;
  const incoming: Uint8Array[] = [];
  return {
    sent,
    get closed() {
      return closed;
    },
    set closed(v) {
      closed = v;
    },
    connect() {
      return Promise.resolve();
    },
    close() {
      closed = true;
      return Promise.resolve();
    },
    send(p) {
      sent.push(p);
    },
    async *receive() {
      for (const p of incoming) yield p;
    },
  };
}

function passthroughCodecs(): CodecFactory {
  // 1 PCM frame → 1 fake packet that just encodes sample count + first sample
  return {
    newEncoder(): AudioEncoder {
      return {
        encode(f: PcmFrame) {
          const buf = new Uint8Array(8);
          new DataView(buf.buffer).setUint32(0, f.samples.length, false);
          new DataView(buf.buffer).setInt16(4, f.samples[0] ?? 0, false);
          return buf;
        },
      };
    },
    newDecoder(): AudioDecoder {
      return {
        decode(p: Uint8Array) {
          const dv = new DataView(p.buffer, p.byteOffset, p.byteLength);
          const n = dv.getUint32(0, false);
          const v = dv.getInt16(4, false);
          const samples = new Int16Array(n);
          samples.fill(v);
          return { samples, sampleRate: 48000, channels: 1 };
        },
      };
    },
  };
}

function codecsWithOneBadPacket(): CodecFactory {
  const base = passthroughCodecs();
  return {
    newEncoder: base.newEncoder,
    newDecoder(opts): AudioDecoder {
      const decoder = base.newDecoder(opts);
      return {
        decode(packet) {
          if (packet[0] === 0xff) throw new Error("malformed opus packet");
          return decoder.decode(packet);
        },
      };
    },
  };
}

Deno.test("CallSession.start → acquiring → connecting → in-call state transitions", async () => {
  const { client, acquired } = fakeClient();
  const session = new CallSession(client, {
    to: "u-peer",
    kind: "AUDIO",
    transport: recordingTransport(),
  });
  const states: string[] = [];
  session.on("state", (s) => states.push(s));
  const route = await session.start();
  assertEquals(states, ["acquiring", "connecting", "in-call"]);
  assertEquals(session.state, "in-call");
  assertEquals(session.peer, "u-peer");
  assertEquals((acquired[0] as { to: string }).to, "u-peer");
  assertEquals((acquired[0] as { callType: string }).callType, "AUDIO");
  assert(route);
});

Deno.test("CallSession.start is idempotent", async () => {
  const { client } = fakeClient();
  const session = new CallSession(client, { to: "u-p", transport: recordingTransport() });
  const r1 = await session.start();
  const r2 = await session.start();
  assertEquals(r1, r2);
});

Deno.test("CallSession starts VIDEO and toggles its media without replacing audio or route", async () => {
  const { client, acquired } = fakeClient();
  const transport = recordingTransport();
  const controls: boolean[] = [];
  let initialKind: string | undefined;
  const videoTransport = {
    ...transport,
    videoAvailable: true,
    connect: async (opts: { kind?: string }) => {
      initialKind = opts.kind;
    },
    setVideoEnabled: async (enabled: boolean) => {
      controls.push(enabled);
    },
  };
  const session = new CallSession(client, { to: "u-p", kind: "VIDEO", transport: videoTransport });
  await session.start();
  await session.setVideoEnabled(true);
  await session.setVideoEnabled(false);
  assertEquals(
    [initialKind, acquired.length, session.state, session.kind],
    ["VIDEO", 1, "in-call", "VIDEO"],
  );
  assertEquals(controls, [true, false]);
  assertEquals(session.videoState, { available: true, localEnabled: false, remoteEnabled: false });
  await session.end();
  await assertRejects(() => session.setVideoEnabled(true), Error, "not in-call");
});

Deno.test("CallSession does not show delayed video after peer camera pause", async () => {
  const transport: CallTransport = {
    ...recordingTransport(),
    videoAvailable: true,
    async *receiveVideo() {
      yield { data: new Uint8Array([1]), key: true, timestamp: 0 };
      transport.onVideoState?.(false);
      yield { data: new Uint8Array([1]), key: true, timestamp: 1 };
      transport.onVideoState?.(true);
      yield { data: new Uint8Array([1]), key: false, timestamp: 2 };
      yield { data: new Uint8Array([1]), key: true, timestamp: 3 };
    },
  };
  const session = new CallSession(fakeClient().client, { to: "u-p", transport });
  await session.start();
  const timestamps: number[] = [];
  for await (const frame of session.receivedVideo()) timestamps.push(frame.timestamp);
  assertEquals(timestamps, [0, 3]);
  await session.end();
});

Deno.test("group video needs a key per member and drops departed sources without pausing others", async () => {
  const members = [1, 2].map((i) => ({
    mid: `u${String(i).repeat(32)}`,
    connected: true,
    mediaFlags: 3,
    sources: [{ name: "V", ssrc: i }],
  }));
  const frame = (index: number, key: boolean, timestamp: number) => ({
    sourceMid: members[index].mid,
    data: new Uint8Array([1]),
    key,
    timestamp,
  });
  const transport: CallTransport = {
    ...recordingTransport(),
    videoAvailable: true,
    async joinGroup() {},
    async *receiveAudio() {},
    async *receiveVideo() {
      transport.onConference?.(members);
      yield frame(0, true, 0);
      yield frame(1, false, 1);
      yield frame(1, true, 2);
      transport.onConference?.(members.slice(1));
      yield frame(0, true, 3);
      yield frame(1, false, 4);
      transport.onConference?.([]);
    },
  };
  const session = new CallSession(fakeClient().client, {
    to: `c${"1".repeat(32)}`,
    transport,
    group: { route: {} as never },
  });
  await session.start();
  const timestamps: number[] = [];
  for await (const item of session.receivedVideo()) timestamps.push(item.timestamp);
  assertEquals(timestamps, [0, 2, 4]);
  assertEquals(session.videoState.remoteEnabled, false);
  await session.end();
});

Deno.test("CallSession.start closes the transport when signaling fails", async () => {
  const { client } = fakeClient();
  let closeCalls = 0;
  const transport: CallTransport = {
    connect() {
      return Promise.reject(new Error("connect failed"));
    },
    close() {
      closeCalls++;
      return Promise.resolve();
    },
    send() {},
    async *receive() {},
  };
  const session = new CallSession(client, { to: "u-p", transport });

  await assertRejects(() => session.start(), Error, "connect failed");
  await session.end("dismiss-failed-call");

  assertEquals(session.state, "failed");
  assertEquals(closeCalls, 1);
});

Deno.test("CallSession.start answers an incoming call without acquiring or inviting", async () => {
  const { client, acquired, fakeRoute } = fakeClient();
  let answered = 0;
  let invited = 0;
  const transport: CallTransport = {
    ...recordingTransport(),
    invite() {
      invited++;
      return Promise.resolve();
    },
    answer() {
      answered++;
      return Promise.resolve();
    },
  };
  const session = new CallSession(client, {
    to: "u-caller",
    kind: "AUDIO",
    direction: "incoming",
    preacquiredRoute: fakeRoute as never,
    transport,
  });
  const states: string[] = [];
  session.on("state", (state) => states.push(state));

  await session.start();

  assertEquals(acquired.length, 0);
  assertEquals(invited, 0);
  assertEquals(answered, 1);
  assertEquals(states, ["acquiring", "connecting", "ringing", "in-call"]);
});

Deno.test("group sessions join a preacquired route without direct-call signaling", async () => {
  const { client, acquired, fakeRoute } = fakeClient();
  const calls: string[] = [];
  const transport: CallTransport = {
    ...recordingTransport(),
    async connect() {
      calls.push("connect");
    },
    async invite() {
      calls.push("invite");
    },
    async joinGroup({ roomId }) {
      calls.push(roomId);
    },
    async *receiveAudio() {},
  };
  const session = new CallSession(client, {
    to: "c-room",
    group: { route: fakeRoute as never },
    transport,
  });
  await session.start();
  assertEquals(acquired, []);
  assertEquals(calls, ["connect", "c-room"]);
  assertEquals(session.state, "in-call");
  await session.end();
  const failing = new CallSession(client, {
    to: "c-room",
    group: { route: fakeRoute as never },
    transport: {
      ...transport,
      async joinGroup() {
        throw new Error("join rejected");
      },
    },
  });
  await assertRejects(() => failing.start(), Error, "join rejected");
  assertEquals(failing.state, "failed");
  await assertRejects(() => failing.start(), Error, "join rejected");
});

Deno.test("ending during signaling cannot resurrect a call", async () => {
  let finishConnect!: () => void;
  const connecting = new Promise<void>((resolve) => {
    finishConnect = resolve;
  });
  const transport = { ...recordingTransport(), connect: () => connecting };
  const session = new CallSession(fakeClient().client, { to: "u-p", transport });
  const pending = session.start();
  await Promise.resolve();
  await session.end();
  finishConnect();
  await assertRejects(() => pending, Error, "Call ended");
  assertEquals(session.state, "ended");
});

Deno.test("group session PCM uses simultaneous playout and closes its receive pump", async () => {
  let finish!: () => void;
  const stopped = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const encoder = passthroughCodecs().newEncoder({ sampleRate: 48000, channels: 1 });
  const transport: CallTransport = {
    ...recordingTransport(),
    async joinGroup() {},
    async close() {
      finish();
    },
    receive() {
      throw new Error("Group audio must not flatten speakers");
    },
    async *receiveAudio() {
      for (const [ssrc, value] of [
        [1, 10],
        [2, 20],
      ])
        yield {
          ssrc,
          timestamp: 960,
          frames: [
            encoder.encode({
              samples: new Int16Array(960).fill(value),
              sampleRate: 48000,
              channels: 1,
            })!,
          ],
        };
      await stopped;
    },
  };
  const session = new CallSession(fakeClient().client, {
    to: "c-room",
    group: { route: fakeClient().fakeRoute as never },
    transport,
    codecs: passthroughCodecs(),
  });
  await session.start();
  try {
    for await (const frame of session.received()) {
      assertEquals(frame.samples.length, 960);
      assertEquals(frame.samples[0], 30);
      break;
    }
    assertEquals(session.state, "ended");
  } finally {
    await session.end();
  }
});

Deno.test("group participant departures discard their buffered and late audio", async () => {
  let finish!: () => void;
  const stopped = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const member = (n: number) => ({
    mid: `u${String(n).padStart(32, "0")}`,
    connected: true,
    mediaFlags: 1,
    sources: [{ name: "A", ssrc: n }],
  });
  const codecs = passthroughCodecs();
  const encoder = codecs.newEncoder({ sampleRate: 48000, channels: 1 });
  let created = 0;
  let closed = 0;
  const transport: CallTransport = {
    ...recordingTransport(),
    async joinGroup() {
      transport.onConference?.([member(1), member(2)]);
    },
    async close() {
      finish();
    },
    async *receiveAudio() {
      for (const [ssrc, timestamp, value] of [
        [1, 960, 10],
        [1, 1920, 10],
        [2, 960, 20],
      ]) {
        if (timestamp === 1920) transport.onConference?.([member(2)]);
        yield {
          ssrc,
          timestamp,
          frames: [
            encoder.encode({
              samples: new Int16Array(960).fill(value),
              sampleRate: 48000,
              channels: 1,
            })!,
          ],
        };
      }
      await stopped;
    },
  };
  const session = new CallSession(fakeClient().client, {
    to: "c-room",
    group: { route: fakeClient().fakeRoute as never },
    transport,
    codecs: {
      ...codecs,
      newDecoder(options) {
        created++;
        const decoder = codecs.newDecoder(options);
        return {
          ...decoder,
          close() {
            closed++;
            decoder.close?.();
          },
        };
      },
    },
  });
  const changes: number[] = [];
  session.on("participants", (members) => changes.push(members.length));
  await session.start();
  assertEquals(session.participants?.length, 2);
  const copy = session.participants!;
  copy[0].sources = [];
  assertEquals(session.participants![0].sources.length, 1);
  try {
    for await (const frame of session.received()) {
      assertEquals(frame.samples[0], 20);
      break;
    }
    assertEquals([created, closed], [2, 2]);
    assertEquals(changes, [2, 1, 0]);
    transport.onConference?.([member(1)]);
    assertEquals(session.participants, []);
  } finally {
    await session.end();
  }
});

Deno.test("CallSession.sendStream pumps PCM through codec → transport", async () => {
  const { client } = fakeClient();
  const transport = recordingTransport();
  const session = new CallSession(client, {
    to: "u-p",
    transport,
    codecs: passthroughCodecs(),
  });
  await session.start();
  const samples = new Int16Array(1600); // 100ms @ 16kHz
  samples.fill(42);
  await session.sendStream(bufferSource({ samples, sampleRate: 16000 }));
  assertEquals(transport.sent.length, 5);
  // each fake-encoded packet starts with the frame's sample count (320)
  const dv = new DataView(transport.sent[0].buffer);
  assertEquals(dv.getUint32(0, false), 320);
  assertEquals(dv.getInt16(4, false), 42);
});

Deno.test("CallSession.sendStream follows a transport 40ms voice profile", async () => {
  const { client } = fakeClient();
  const sent: Uint8Array[] = [];
  const encodedLengths: number[] = [];
  const audioLevels: Array<number | undefined> = [];
  let encoderOptions: Parameters<CodecFactory["newEncoder"]>[0] | undefined;
  const transport: CallTransport = {
    audioProfile: {
      frameDurationMs: 40,
      bitrate: 16000,
      bandwidth: "fullband",
      signal: "voice",
      vbr: false,
    },
    connect: () => Promise.resolve(),
    close: () => Promise.resolve(),
    send(packet, options) {
      sent.push(packet);
      audioLevels.push(options?.audioLevel);
    },
    async *receive() {},
  };
  const codecs: CodecFactory = {
    newEncoder(opts): AudioEncoder {
      encoderOptions = opts;
      return {
        encode(frame) {
          encodedLengths.push(frame.samples.length);
          return new Uint8Array([frame.samples.length >>> 8, frame.samples.length & 0xff]);
        },
      };
    },
    newDecoder(): AudioDecoder {
      return { decode: () => null };
    },
  };
  const session = new CallSession(client, { to: "u-p", transport, codecs });
  await session.start();
  const samples = new Int16Array(1920);
  for (let i = 0; i < samples.length; i++) samples[i] = i % 2 ? 123 : -123;

  await session.sendStream(bufferSource({ samples, sampleRate: 48000, frameDurationMs: 20 }));

  assertEquals(sent.length, 1);
  assertEquals(audioLevels, [49]);
  assertEquals(encodedLengths, [1920]);
  assertEquals(encoderOptions?.frameDurationMs, 40);
  assertEquals(encoderOptions?.bitrate, 16000);
  assertEquals(encoderOptions?.bandwidth, "fullband");
  assertEquals(encoderOptions?.signal, "voice");
  assertEquals(encoderOptions?.vbr, false);
});

Deno.test("CallSession.sendStream rejects when not in-call", async () => {
  const { client } = fakeClient();
  const session = new CallSession(client, { to: "u-p", transport: recordingTransport() });
  await assertRejects(
    () => session.sendStream(bufferSource({ samples: new Int16Array(0), sampleRate: 48000 })),
    Error,
    "not in-call",
  );
});

Deno.test("CallSession.received yields decoded peer PCM frames", async () => {
  const { client } = fakeClient();
  // Build a transport that emits 3 fake packets
  const transport: CallTransport = {
    connect() {
      return Promise.resolve();
    },
    close() {
      return Promise.resolve();
    },
    send() {},
    async *receive() {
      for (const v of [10, 20, 30]) {
        const buf = new Uint8Array(8);
        new DataView(buf.buffer).setUint32(0, 5, false);
        new DataView(buf.buffer).setInt16(4, v, false);
        yield buf;
      }
    },
  };
  const session = new CallSession(client, {
    to: "u-p",
    transport,
    codecs: passthroughCodecs(),
  });
  await session.start();
  const collected: number[] = [];
  for await (const f of session.received()) collected.push(f.samples[0]);
  assertEquals(collected, [10, 20, 30]);
});

Deno.test("CallSession.received skips one malformed audio packet and keeps receiving", async () => {
  const { client } = fakeClient();
  const good = new Uint8Array(8);
  new DataView(good.buffer).setUint32(0, 1, false);
  new DataView(good.buffer).setInt16(4, 77, false);
  const transport: CallTransport = {
    connect: () => Promise.resolve(),
    close: () => Promise.resolve(),
    send() {},
    async *receive() {
      yield new Uint8Array([0xff]);
      yield good;
    },
  };
  const session = new CallSession(client, {
    to: "u-p",
    transport,
    codecs: codecsWithOneBadPacket(),
  });
  await session.start();

  const collected: number[] = [];
  for await (const frame of session.received()) collected.push(frame.samples[0]);

  assertEquals(collected, [77]);
});

Deno.test("CallSession.receiveInto pipes to AudioSink + closes on stream end", async () => {
  const { client } = fakeClient();
  const transport: CallTransport = {
    connect() {
      return Promise.resolve();
    },
    close() {
      return Promise.resolve();
    },
    send() {},
    async *receive() {
      const buf = new Uint8Array(8);
      new DataView(buf.buffer).setUint32(0, 2, false);
      new DataView(buf.buffer).setInt16(4, 99, false);
      yield buf;
    },
  };
  const session = new CallSession(client, {
    to: "u-p",
    transport,
    codecs: passthroughCodecs(),
  });
  await session.start();
  const sink = bufferSink();
  await session.receiveInto(sink);
  assertEquals(sink.frames.length, 1);
  assertEquals(sink.frames[0].samples[0], 99);
});

Deno.test("CallSession.receiveInto skips one malformed audio packet and keeps receiving", async () => {
  const { client } = fakeClient();
  const good = new Uint8Array(8);
  new DataView(good.buffer).setUint32(0, 1, false);
  new DataView(good.buffer).setInt16(4, 88, false);
  const transport: CallTransport = {
    connect: () => Promise.resolve(),
    close: () => Promise.resolve(),
    send() {},
    async *receive() {
      yield new Uint8Array([0xff]);
      yield good;
    },
  };
  const session = new CallSession(client, {
    to: "u-p",
    transport,
    codecs: codecsWithOneBadPacket(),
  });
  await session.start();
  const sink = bufferSink();

  await session.receiveInto(sink);

  assertEquals(sink.frames.length, 1);
  assertEquals(sink.frames[0].samples[0], 88);
});

Deno.test("CallSession.end transitions to ending → ended + emits 'ended'", async () => {
  const { client } = fakeClient();
  const transport = recordingTransport();
  const session = new CallSession(client, { to: "u-p", transport });
  await session.start();
  const states: string[] = [];
  session.on("state", (s) => states.push(s));
  let endedReason = "";
  session.on("ended", (r) => (endedReason = r));
  await session.end("hung-up");
  assertEquals(states, ["ending", "ended"]);
  assertEquals(endedReason, "hung-up");
  assert(transport.closed);
});

Deno.test("CallSession.end shares cleanup across concurrent callers", async () => {
  const { client } = fakeClient();
  let transportCloseCalls = 0;
  let encoderCloseCalls = 0;
  let decoderCloseCalls = 0;
  const transport: CallTransport = {
    connect: () => Promise.resolve(),
    close() {
      transportCloseCalls++;
      return Promise.resolve();
    },
    send() {},
    async *receive() {},
  };
  const codecs: CodecFactory = {
    newEncoder(): AudioEncoder {
      return {
        encode: () => new Uint8Array([1]),
        close: () => encoderCloseCalls++,
      };
    },
    newDecoder(): AudioDecoder {
      return {
        decode: () => null,
        close: () => decoderCloseCalls++,
      };
    },
  };
  const session = new CallSession(client, { to: "u-p", transport, codecs });
  await session.start();
  await session.sendStream(bufferSource({ samples: new Int16Array(960), sampleRate: 48000 }));
  await session.received().next();
  const endedReasons: string[] = [];
  session.on("ended", (reason) => endedReasons.push(reason));

  const first = session.end("first");
  const second = session.end("second");
  assert(first === second);
  await Promise.all([first, second]);

  assertEquals(transportCloseCalls, 1);
  assertEquals(encoderCloseCalls, 1);
  assertEquals(decoderCloseCalls, 1);
  assertEquals(endedReasons, ["first"]);
});

Deno.test("stub transport throws on connect", async () => {
  const { client } = fakeClient();
  const session = new CallSession(client, { to: "u-p" }); // no transport
  const errors: Error[] = [];
  session.on("error", (e) => errors.push(e));
  await assertRejects(() => session.start(), Error, "CallTransport not configured");
  assertEquals(session.state, "failed");
  assertEquals(errors.length, 1);
});

Deno.test("CallSession.sendFile uses caller-supplied decoder", async () => {
  const { client } = fakeClient();
  const transport = recordingTransport();
  const session = new CallSession(client, {
    to: "u-p",
    transport,
    codecs: passthroughCodecs(),
  });
  await session.start();
  // Caller-supplied decoder turns the byte 0xAB into PCM samples
  const decode = (bytes: Uint8Array) => ({
    samples: new Int16Array(800).fill(bytes[0]),
    sampleRate: 16000,
    channels: 1,
  });
  await session.sendFile({ bytes: new Uint8Array([0xab]), decode });
  // 800 samples / 320-per-frame = 3 frames (2 full + 1 remainder)
  assertEquals(transport.sent.length, 3);
});
