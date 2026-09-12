import { assert, assertEquals, assertRejects } from "@vyline/protocol/stack/assert";
import { Buffer } from "node:buffer";
import { createSocket, type RemoteInfo, type Socket } from "node:dgram";
import {
  aesCtrDecrypt,
  aesCtrEncrypt,
  buildDirectionLabel,
  buildPlanetCtrIv,
  deriveCallKeys,
  derivePlanetMediaKeys,
  derivePlanetMediaStreamKeying,
  type EphemeralKeypair,
  generateEphemeralKeypair,
  hmacTag,
  sha256,
  tagEquals,
  type TransportKeys,
} from "./crypto.ts";
import { makeChunkHdr } from "./framing.ts";
import {
  CC_MSG,
  decodeCcConnReq,
  decodeCcRelReq,
  decodeFields,
  decodeMcDataRsp,
  decodeMcDataReq,
  decodeMcStreamControl,
  decodeNativeSetupOffer,
  decodePlanetMsg,
  MC_MSG,
  packCcConnReq,
  packCcConnRsp,
  packCcInfoReq,
  packCcRelReq,
  packCcSetupRsp,
  packCcVerifyRsp,
  packMcDataReq,
  packMcDataRsp,
  packNativeGroupParticipateOffer,
  packNativeSetupOffer,
  packPlanetCcMsg,
  packPlanetMcMsg,
  packPlanetMsg,
  packPlanetUserAgent,
  packPlanetAddr,
  type PlanetSetupOfferMaterial,
  wrapCcMsg,
  wrapMcMsg,
} from "./schema.ts";
import { PlanetTransport } from "./transport.ts";
import { encodePb } from "./cassini.ts";
import { depacketizeEas2 } from "./eas2.ts";
import { Evs3Assembler, packetizeEvs3, parseEvs3 } from "./evs3.ts";
import { packetizeSvcVp8, parseSvcVfd, unwrapSvcVp8 } from "./svc.ts";
import { buildPdtp, pdtpUint } from "./pdtp.ts";
import { buildRtp, deriveSrtpContext, parseRtp, srtpDecrypt, srtpEncrypt } from "../srtp.ts";

type CallRouteLike = Parameters<PlanetTransport["connect"]>[0]["route"];

const HEADER_LEN = 6;
const BOOTSTRAP_PREFIX_LEN = 51;
const BOOTSTRAP_SEC_HEADER_LEN = 5;
const REGULAR_TAIL_CONTROL_BASE = 0x18;

function bytesToBase64(bytes: Uint8Array): string {
  let raw = "";
  for (const b of bytes) raw += String.fromCharCode(b);
  return btoa(raw);
}

function makeRoute(peer = generateEphemeralKeypair(), port = 9): CallRouteLike {
  return {
    voipAddress: "127.0.0.1",
    voipUdpPort: port,
    voipAddress6: "",
    toMid: "u-peer",
    fromToken: "from-token",
    fromZone: "JP",
    toZone: "JP",
    commParam: JSON.stringify({ mpkey: bytesToBase64(peer.publicKey) }),
    stid: "stid",
    stnpk: "stnpk",
  } as unknown as CallRouteLike;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

Deno.test("Planet audio decodes native EAS2 even without a Vyline device marker", () => {
  const nativePayload = new Uint8Array([0x70, 0xf9, 0xff, 0xfd]);
  assertEquals(depacketizeEas2(nativePayload), [new Uint8Array([0xf8, 0xff, 0xfd])]);
});

function buildBootstrapSecHeader(plaintextLen: number): Uint8Array {
  return new Uint8Array([0, 0, 0, 0x28 | ((plaintextLen >>> 8) & 0x07), plaintextLen & 0xff]);
}

function buildBootstrapFrameHeader(totalLen: number, sequence: number): Uint8Array {
  const chunkLogical = ((((totalLen - 4) << 5) | 0x1d) & 0xffff) >>> 0;
  const chunk = makeChunkHdr(chunkLogical);
  return new Uint8Array([
    chunk & 0xff,
    (chunk >>> 8) & 0xff,
    (sequence >>> 8) & 0xff,
    sequence & 0xff,
    0x06,
    0x02,
  ]);
}

function buildRegularFrameHeader(
  totalLen: number,
  sequence: number,
  plaintextLen: number,
): Uint8Array {
  const chunkLogical = ((((totalLen - 4) << 5) | 0x0d) & 0xffff) >>> 0;
  const chunk = makeChunkHdr(chunkLogical);
  const tail16 =
    (((REGULAR_TAIL_CONTROL_BASE | ((plaintextLen >>> 8) & 0x07)) << 8) | (plaintextLen & 0xff)) &
    0xffff;
  return new Uint8Array([
    chunk & 0xff,
    (chunk >>> 8) & 0xff,
    (sequence >>> 8) & 0xff,
    sequence & 0xff,
    (tail16 >>> 8) & 0xff,
    tail16 & 0xff,
  ]);
}

function buildServerWire(
  keys: TransportKeys,
  plaintext: Uint8Array,
  sequence: number,
  opts: { bootstrap?: { label: number; seed: Uint8Array; pub: Uint8Array } } = {},
): Uint8Array {
  const ct = aesCtrEncrypt(keys.encKey, buildPlanetCtrIv(keys.ctrBase, sequence), plaintext);
  const tagLen = 16;
  if (opts.bootstrap) {
    const prefix = concatBytes([
      buildDirectionLabel(opts.bootstrap.label),
      opts.bootstrap.seed,
      opts.bootstrap.pub,
    ]);
    assertEquals(prefix.length, BOOTSTRAP_PREFIX_LEN);
    const sec = buildBootstrapSecHeader(plaintext.length);
    assertEquals(sec.length, BOOTSTRAP_SEC_HEADER_LEN);
    const totalLen = HEADER_LEN + prefix.length + sec.length + ct.length + tagLen;
    const hdr = buildBootstrapFrameHeader(totalLen, sequence);
    const macInput = concatBytes([hdr, prefix, sec, ct]);
    return concatBytes([macInput, hmacTag(keys.macKey, macInput)]);
  }
  const totalLen = HEADER_LEN + ct.length + tagLen;
  const hdr = buildRegularFrameHeader(totalLen, sequence, plaintext.length);
  const macInput = concatBytes([hdr, ct]);
  return concatBytes([macInput, hmacTag(keys.macKey, macInput)]);
}

function buildControlPlain(opts: {
  bodyTag: number;
  bodyBytes: Uint8Array;
  msgId: number;
  sessId: Uint8Array;
  locNonce: bigint;
  cid: string;
  srcChanId: bigint;
  dstChanId?: bigint;
}): Uint8Array {
  const tranId = new Uint8Array(16);
  tranId.fill(opts.msgId & 0xff);
  return packPlanetMsg(
    {
      userId: "u-server",
      msgId: opts.msgId,
      sessId: opts.sessId,
      tranId,
      tranSeq: opts.msgId,
      locNonce: opts.locNonce,
      rmtNonce: 0n,
    },
    {
      kind: "cc",
      data: packPlanetCcMsg(
        {
          cid: opts.cid,
          srcChanId: opts.srcChanId,
          dstChanId: opts.dstChanId ?? 0n,
        },
        wrapCcMsg(opts.bodyTag, opts.bodyBytes),
      ),
    },
  );
}

function buildMediaControlPlain(opts: {
  bodyTag: number;
  bodyBytes: Uint8Array;
  msgId: number;
  sessId: Uint8Array;
  locNonce: bigint;
  cid: string;
  srcChanId: bigint;
  dstChanId?: bigint;
}): Uint8Array {
  const tranId = new Uint8Array(16);
  tranId.fill(opts.msgId & 0xff);
  return packPlanetMsg(
    {
      userId: "u-server",
      msgId: opts.msgId,
      sessId: opts.sessId,
      tranId,
      tranSeq: opts.msgId,
      locNonce: opts.locNonce,
      rmtNonce: 0n,
    },
    {
      kind: "mc",
      data: packPlanetMcMsg(
        {
          cid: opts.cid,
          srcChanId: opts.srcChanId,
          dstChanId: opts.dstChanId ?? 0n,
        },
        wrapMcMsg(opts.bodyTag, opts.bodyBytes),
      ),
    },
  );
}

function extractBootstrapClientPub(wire: Uint8Array): Uint8Array {
  return wire.subarray(HEADER_LEN + 2 + 16, HEADER_LEN + 2 + 16 + 33);
}

function extractBootstrapClientLabel(wire: Uint8Array): number {
  return ((wire[HEADER_LEN] << 8) | wire[HEADER_LEN + 1]) & 0xffff;
}

function extractBootstrapClientSeed(wire: Uint8Array): Uint8Array {
  return new Uint8Array(wire.subarray(HEADER_LEN + 2, HEADER_LEN + 18));
}

function decryptRegularWire(keys: TransportKeys, wire: Uint8Array): Uint8Array | undefined {
  const tag = wire.subarray(wire.length - 16);
  const macInput = wire.subarray(0, wire.length - 16);
  const expected = hmacTag(keys.macKey, macInput);
  if (!tagEquals(tag, expected)) return undefined;
  const seq = ((wire[2] << 8) | wire[3]) & 0xffff;
  const ct = wire.subarray(HEADER_LEN, wire.length - 16);
  return aesCtrDecrypt(keys.encKey, buildPlanetCtrIv(keys.ctrBase, seq), ct);
}

function isRtpLike(wire: Uint8Array): boolean {
  return wire.length >= 12 && (wire[0] & 0xc0) === 0x80;
}

async function bindUdpServer(): Promise<Socket> {
  const server = createSocket("udp4");
  await new Promise<void>((resolve) =>
    server.bind({ address: "127.0.0.1", port: 0 }, () => resolve()),
  );
  return server;
}

async function sendUdp(server: Socket, packet: Uint8Array, rinfo: RemoteInfo): Promise<void> {
  await new Promise<void>((resolve, reject) =>
    server.send(Buffer.from(packet), rinfo.port, rinfo.address, (err) =>
      err ? reject(err) : resolve(),
    ),
  );
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`${label} timeout`)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (err) => {
        clearTimeout(timeout);
        reject(err);
      },
    );
  });
}

Deno.test("PlanetTransport.close does not send REL before SETUP/INVITE", async () => {
  let sends = 0;
  const transport = new PlanetTransport({
    localMid: "u-local",
    wireSend() {
      sends++;
    },
  });

  await transport.connect({ route: makeRoute() });
  await transport.close();

  assertEquals(sends, 0);
});

Deno.test("PlanetTransport retains generated media offer material for SRTP setup", async () => {
  let sends = 0;
  let setupMsgId = 0;
  const transport = new PlanetTransport({
    localMid: "u-local",
    timeoutMs: 1,
    wireSend(_packet, endpoint) {
      sends++;
      if (endpoint.bootstrap) {
        setupMsgId = decodePlanetMsg(endpoint.plaintext).hdr?.msgId ?? 0;
      }
    },
  });

  await transport.connect({ route: makeRoute() });
  try {
    await transport.invite({ to: "u-peer" });
  } catch (e) {
    assert(e instanceof Error);
    assert(e.message.includes("PLANET reply timeout"));
  }

  const media = transport.localMediaOffer;
  assert(media);
  assertEquals(sends, 1);
  assertEquals(setupMsgId, 0x2141);
  assertEquals(media.keypair.publicKey.length, 33);
  assertEquals(media.keypair.privateKey.length, 32);
  assertEquals(media.material.mediaPubKey.length, 33);
  assertEquals(media.material.mediaNonce.length, 16);
  assertEquals(media.material.mediaSecret.length, 30);
  assertEquals(media.offer.length, 311);
});

for (const kind of ["AUDIO", "VIDEO"] as const) {
  Deno.test(`group participate preserves requested ${kind} kind`, async () => {
    let request: ReturnType<typeof decodeFields> = [];
    const transport = new PlanetTransport({
      localMid: "u-local",
      timeoutMs: 1,
      wireSend(_packet, endpoint) {
        if (!endpoint.bootstrap) return;
        const msg = decodePlanetMsg(endpoint.plaintext);
        if (msg.cc?.bodyTag === CC_MSG.PARTICIPATE_REQ) request = decodeFields(msg.cc.bodyBytes!);
      },
    });
    await transport.connect({
      kind,
      route: {
        voipAddress: "127.0.0.1",
        voipUdpPort: 9,
        commParam: makeRoute().commParam,
        token: "test-token",
        hostMid: "u-local",
      } as CallRouteLike,
    });
    try {
      await assertRejects(() => transport.joinGroupDetailed({ roomId: "c-room" }), Error, "PLANET reply timeout");
      assertEquals(request.find((f) => f.tag === 9)?.value, kind === "VIDEO" ? 3n : 1n);
      assertEquals(
        new TextDecoder().decode(request.find((f) => f.tag === 13)!.value as Uint8Array),
        kind === "VIDEO" ? "groupcall.video" : "groupcall.audio",
      );
      const offer = decodeNativeSetupOffer(request.find((f) => f.tag === 11)!.value as Uint8Array);
      assertEquals(offer.media.find((m) => m.name === "V")?.enabled, kind === "VIDEO" ? 1 : 0);
    } finally {
      await transport.close();
    }
  });
}

for (const outcome of [
  "accepted",
  "accepted-data",
  "accepted-video",
  "remote-end",
  "rejected",
  "no-media",
] as const) {
  Deno.test(`group participate ${outcome}: verifies join before media and uses negotiated bridge`, async () => {
    const peer = generateEphemeralKeypair();
    const cid = "group-test";
    const seed = new Uint8Array(16).fill(8);
    const peerSecret = new Uint8Array(30).fill(7);
    const mediaWire: Array<{ packet: Uint8Array; port: number }> = [];
    const mcTags: number[] = [];
    const releases: ReturnType<typeof decodeCcRelReq>[] = [];
    const subscriptions: ReturnType<typeof decodePlanetMsg>[] = [];
    const notifyAcks: ReturnType<typeof decodePlanetMsg>[] = [];
    const publisherAcks: ReturnType<typeof decodePlanetMsg>[] = [];
    let mediaChannel = 0n;
    let subscribed!: () => void;
    const subscriptionSeen = new Promise<void>((resolve) => {
      subscribed = resolve;
    });
    let offered: Uint8Array | undefined;
    let serverKeys: TransportKeys | undefined;
    let incoming: Uint8Array | undefined;
    let remoteRelease: Uint8Array | undefined;
    let releaseNow = false;
    let receivedData!: () => void;
    const dataSeen = new Promise<void>((resolve) => {
      receivedData = resolve;
    });
    const inner = [11, 22].map((ssrc) =>
      buildRtp({
        payloadType: 96,
        ssrc,
        seq: 1,
        timestamp: 960,
        payload: new Uint8Array([0x10, 0xf9, 0xff, 0xfd]),
      }),
    );
    incoming = await srtpEncrypt(
      await deriveSrtpContext(derivePlanetMediaStreamKeying(peerSecret, "AUDIO")),
      buildRtp({
        payloadType: 96,
        ssrc: 100,
        seq: 1,
        timestamp: 960,
        payload: concatBytes(inner),
        extensionProfile: 0x0240,
        extensionData: new Uint8Array([3, 1, 16, 16]),
      }),
    );
    if (outcome === "accepted-data")
      incoming = await srtpEncrypt(
        await deriveSrtpContext(derivePlanetMediaStreamKeying(peerSecret, "DATA")),
        buildRtp({
          payloadType: 98,
          ssrc: 300,
          seq: 1,
          timestamp: 0,
          payload: new Uint8Array([
            0x80,
            0,
            ...new TextEncoder().encode("PLANET"),
            0,
            0,
            8,
            4,
            1,
            1,
            0x12,
            0,
          ]),
          extensionProfile: 0x0240,
        }),
      );
    const transport = new PlanetTransport({
      localMid: "u-local",
      callId: cid,
      timeoutMs: 500,
      keepaliveIntervalMs: outcome === "remote-end" || outcome === "accepted-video" ? 10 : 0,
      debug(event) {
        if (event.type === "group_pdtp_handled") receivedData();
      },
      wireSend(packet, endpoint) {
        if (isRtpLike(packet)) {
          mediaWire.push({ packet, port: endpoint.port });
          return;
        }
        if (endpoint.plaintext.length === 519 || endpoint.plaintext.length === 10) return;
        const msg = decodePlanetMsg(endpoint.plaintext);
        if (msg.hdr?.msgId === 0x1101) {
          if (releaseNow) {
            const release = remoteRelease;
            remoteRelease = undefined;
            return release;
          }
          const reply = incoming;
          incoming = undefined;
          return reply;
        }
        if (msg.mc?.bodyTag !== undefined) mcTags.push(msg.mc.bodyTag);
        if (msg.mc?.bodyTag === MC_MSG.STRM_REQ && serverKeys) {
          subscriptions.push(msg);
          if (subscriptions.length === 2) subscribed();
          const reply = buildServerWire(
            serverKeys,
            packPlanetMsg(
              { ...msg.hdr!, msgId: 0x328d, locNonce: 123n },
              {
                kind: "mc",
                data: packPlanetMcMsg(
                  { cid, srcChanId: 123n, dstChanId: mediaChannel },
                  wrapMcMsg(MC_MSG.STRM_RSP, packMcDataRsp({ result: 0, relCode: 0 })),
                ),
              },
            ),
            0x5004,
          );
          return subscriptions.length === 2
            ? new Promise<Uint8Array>((resolve) => setTimeout(() => resolve(reply), 100))
            : reply;
        }
        if (msg.mc?.bodyTag === MC_MSG.NOTIFY_STRM_RSP) notifyAcks.push(msg);
        if (msg.mc?.bodyTag === MC_MSG.STRM_RSP) publisherAcks.push(msg);
        if (msg.mc?.bodyTag === MC_MSG.DATA_REQ && serverKeys) {
          mediaChannel = msg.mc.hdr!.srcChanId!;
          const request = decodeMcDataReq(msg.mc.bodyBytes!);
          const control = decodeMcStreamControl(request.data);
          if (control)
            return buildServerWire(
              serverKeys,
              packPlanetMsg(
                {
                  ...msg.hdr!,
                  userId: "u-server",
                  msgId: 0x3289,
                  locNonce: 123n,
                },
                {
                  kind: "mc",
                  data: packPlanetMcMsg(
                    { cid, srcChanId: 123n, dstChanId: msg.mc.hdr?.srcChanId },
                    wrapMcMsg(
                      MC_MSG.DATA_RSP,
                      packMcDataRsp({ result: 0, dispatchId: 2, data: request.data }),
                    ),
                  ),
                },
              ),
              0x5003,
            );
        }
        if (msg.cc?.bodyTag === CC_MSG.REL_REQ) releases.push(decodeCcRelReq(msg.cc.bodyBytes!));
        if (msg.cc?.bodyTag !== CC_MSG.PARTICIPATE_REQ) return;
        offered = decodeFields(msg.cc.bodyBytes!).find((f) => f.tag === 11)?.value as Uint8Array;
        const keys = deriveCallKeys({
          mpkey: extractBootstrapClientPub(packet),
          local: peer,
          bootstrapSeed: seed,
          sendLabel: 0x3456,
          recvLabel: 0x3456,
        }).send;
        serverKeys = keys;
        const answer =
          outcome === "no-media"
            ? new Uint8Array()
            : packNativeGroupParticipateOffer({ mediaSecret: peerSecret });
        remoteRelease = buildServerWire(
          keys,
          buildControlPlain({
            bodyTag: CC_MSG.REL_REQ,
            bodyBytes: packCcRelReq({ relCode: 2, releaser: "server", roomDestroy: false }),
            msgId: 0x2245,
            sessId: seed,
            locNonce: 123n,
            cid,
            srcChanId: 123n,
          }),
          0x5002,
        );
        const body = encodePb([
          { tag: 1, wireType: 0, value: outcome === "rejected" ? 1n : 0n },
          { tag: 6, wireType: 2, value: answer },
          { tag: 7, wireType: 0, value: 123n },
          ...(outcome === "accepted-video"
            ? [
                { tag: 8, wireType: 0 as const, value: 1n },
                {
                  tag: 9,
                  wireType: 2 as const,
                  value: encodePb([
                    { tag: 1, wireType: 0, value: 1n },
                    { tag: 2, wireType: 0, value: 1n },
                    ...[31, 32].map((ssrc) => ({
                      tag: 50,
                      wireType: 2 as const,
                      value: encodePb([
                        {
                          tag: 1,
                          wireType: 2,
                          value: new TextEncoder().encode(`u${String(ssrc).padStart(32, "0")}`),
                        },
                        { tag: 3, wireType: 0, value: 1n },
                        {
                          tag: 10,
                          wireType: 2,
                          value: encodePb([
                            { tag: 1, wireType: 2, value: new TextEncoder().encode("V") },
                            { tag: 2, wireType: 0, value: BigInt(ssrc) },
                          ]),
                        },
                      ]),
                    })),
                  ]),
                },
              ]
            : []),
          {
            tag: 101,
            wireType: 2,
            value: encodePb([
              { tag: 1, wireType: 2, value: packPlanetAddr({ ip: "127.0.0.2", port: 12345 }) },
            ]),
          },
        ]);
        return buildServerWire(
          keys,
          buildControlPlain({
            bodyTag: CC_MSG.PARTICIPATE_RSP,
            bodyBytes: body,
            msgId: 0x2261,
            sessId: seed,
            locNonce: 123n,
            cid,
            srcChanId: 123n,
          }),
          0x5001,
          { bootstrap: { label: 0x3456, seed, pub: peer.publicKey } },
        );
      },
    });
    await transport.connect({
      route: {
        voipAddress: "127.0.0.1",
        voipUdpPort: 9,
        commParam: JSON.stringify({ mpkey: bytesToBase64(peer.publicKey) }),
        token: "test-token",
        hostMid: "u-local",
      } as CallRouteLike,
    });
    try {
      if (outcome === "rejected" || outcome === "no-media") {
        await assertRejects(() => transport.joinGroupDetailed({ roomId: "c-room" }));
        if (outcome === "rejected") assertEquals(mcTags.includes(MC_MSG.DATA_REQ), false);
        return;
      }
      const result = await transport.joinGroupDetailed({ roomId: "c-room" });
      assertEquals(result.mediaReady, true);
      if (outcome === "accepted-video") {
        assertEquals(transport.videoAvailable, true);
        const receivedAudio = transport.receiveAudio()[Symbol.asyncIterator]();
        for (const ssrc of [11, 22]) assertEquals((await receivedAudio.next()).value?.ssrc, ssrc);
        const pendingAudio = receivedAudio.next(); // DATA notifier is pumped with audio.
        const channel = encodePb([
          {
            tag: 2,
            wireType: 2,
            value: encodePb([
              {
                tag: 2,
                wireType: 2,
                value: encodePb([
                  { tag: 1, wireType: 0, value: 1n },
                  { tag: 2, wireType: 0, value: 42n },
                  ...[31, 32].map((ssrc) => ({
                    tag: 11,
                    wireType: 2 as const,
                    value: encodePb([
                      {
                        tag: 1,
                        wireType: 2,
                        value: new TextEncoder().encode(`u${String(ssrc).padStart(32, "0")}`),
                      },
                      { tag: 3, wireType: 0, value: 1n },
                      {
                        tag: 11,
                        wireType: 2,
                        value: encodePb([
                          { tag: 1, wireType: 2, value: new TextEncoder().encode("V") },
                          { tag: 2, wireType: 0, value: BigInt(ssrc) },
                        ]),
                      },
                    ]),
                  })),
                ]),
              },
            ]),
          },
        ]);
        incoming = await srtpEncrypt(
          await deriveSrtpContext(derivePlanetMediaStreamKeying(peerSecret, "DATA")),
          buildRtp({
            payloadType: 98,
            ssrc: 300,
            seq: 1,
            timestamp: 0,
            extensionProfile: 0x0240,
            payload: buildPdtp({
              number: 1n,
              service: "PLANET",
              sections: [
                { type: 4, body: new Uint8Array([1, 1, 0, 0]) },
                {
                  type: 1,
                  body: new Uint8Array([
                    1,
                    1,
                    0x1e,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ...pdtpUint(BigInt(channel.length)),
                    ...channel,
                  ]),
                },
              ],
            }),
          }),
        );
        await withTimeout(subscriptionSeen, 500, "group video subscription");
        assertEquals(subscriptions[0].hdr?.msgId, 0x318d);
        assertEquals(subscriptions[0].mc?.hdr, { cid, srcChanId: mediaChannel, dstChanId: 123n });
        const requests = decodeFields(subscriptions[1].mc!.bodyBytes!)
          .filter((f) => f.tag === 1)
          .map((f) => decodeFields(f.value as Uint8Array));
        assertEquals(
          requests.map((f) => [
            f.find((v) => v.tag === 3)?.value,
            f.find((v) => v.tag === 7)?.value,
          ]),
          [
            [31n, 0n],
            [32n, 0n],
            [31n, 42n],
            [32n, 42n],
          ],
        );
        let pendingSources = [31, 32];
        transport.onConference = (members) => {
          pendingSources = members.flatMap((m) =>
            m.sources.filter((s) => s.name === "V").map((s) => s.ssrc),
          );
        };
        incoming = buildServerWire(
          serverKeys!,
          packPlanetMsg(
            { ...subscriptions[0].hdr!, msgId: 0x318f, locNonce: 123n },
            {
              kind: "mc",
              data: packPlanetMcMsg(
                { cid, srcChanId: 123n, dstChanId: mediaChannel },
                wrapMcMsg(MC_MSG.NOTIFY_STRM_REQ, new Uint8Array([10, 6, 8, 1, 24, 31, 40, 99])),
              ),
            },
          ),
          0x5200,
        );
        await new Promise((resolve) => setTimeout(resolve, 30));
        assertEquals(pendingSources, [31, 32]); // Known channel 42 applies even while its STRM ACK is pending.
        notifyAcks.length = 0;
        await new Promise((resolve) => setTimeout(resolve, 90));
        const vp8 = new Uint8Array([0x30, 0, 0, 0x9d, 1, 0x2a, 0x80, 2, 0x68, 1, 0, 0]);
        await transport.setVideoEnabled(true);
        const beforeDemand = mediaWire.length;
        await transport.sendVideo({ data: vp8, key: true, timestamp: 9000 });
        assertEquals(mediaWire.length, beforeDemand);
        incoming = buildServerWire(
          serverKeys!,
          packPlanetMsg(
            { ...subscriptions[0].hdr!, msgId: 0x318d, locNonce: 123n },
            {
              kind: "mc",
              data: packPlanetMcMsg(
                { cid, srcChanId: 123n, dstChanId: mediaChannel },
                wrapMcMsg(
                  MC_MSG.STRM_REQ,
                  encodePb([
                    {
                      tag: 1,
                      wireType: 2,
                      value: encodePb([
                        { tag: 1, wireType: 0, value: 1n },
                        { tag: 3, wireType: 0, value: 213n },
                        { tag: 6, wireType: 0, value: 1n },
                        { tag: 8, wireType: 2, value: new Uint8Array([8, 2, 16, 0]) },
                      ]),
                    },
                  ]),
                ),
              ),
            },
          ),
          0x5007,
        );
        await new Promise((resolve) => setTimeout(resolve, 30));
        await transport.sendVideo({ data: vp8, key: true, timestamp: 9000 });
        const videoRx = await deriveSrtpContext(
          derivePlanetMediaStreamKeying(transport.localMediaOffer!.material.mediaSecret, "VIDEO"),
        );
        const sent = parseRtp(await srtpDecrypt(videoRx, mediaWire.pop()!.packet));
        assertEquals(
          [sent.payloadType, sent.ssrc, sent.timestamp, sent.extensionProfile],
          [97, 213, 9000, 0x0200],
        );
        // The relay requires the outgoing VFD even when received packets omit it.
        assertEquals(parseSvcVfd(sent.extensionData!, sent.payload), sent.seq);
        assertEquals((sent.payload[4] >>> 1) & 15, 2); // 640x360 is native resolution class 2.
        assertEquals(
          new Evs3Assembler().push({ ...sent, payload: unwrapSvcVp8(sent.payload) })?.data,
          vp8,
        );
        await transport.setVideoEnabled(false);
        await assertRejects(() => transport.sendVideo({ data: vp8, key: true, timestamp: 9100 }));
        const videoTx = await deriveSrtpContext(derivePlanetMediaStreamKeying(peerSecret, "VIDEO"));
        const videoReceived = transport.receiveVideo()[Symbol.asyncIterator]();
        for (const ssrc of [31, 32]) {
          const part = packetizeSvcVp8(vp8, true, 1, 1, 2)[0];
          incoming = await srtpEncrypt(
            videoTx,
            buildRtp({
              payloadType: 97,
              ssrc,
              seq: 1,
              timestamp: 9000,
              marker: true,
              payload: part.payload,
              extensionProfile: 0x0240,
              extensionData: part.extensionData,
            }),
          );
          const frame = (await withTimeout(videoReceived.next(), 500, "group participant video"))
            .value;
          assertEquals(frame?.data, vp8);
          assertEquals(frame?.sourceMid, `u${String(ssrc).padStart(32, "0")}`);
        }
        const notify = (state: number, foreign = false) =>
          buildServerWire(
            serverKeys!,
            packPlanetMsg(
              {
                ...subscriptions[0].hdr!,
                sessId: seed,
                userId: "u-server",
                msgId: 0x318f,
                tranId: new Uint8Array([state + 1]),
                locNonce: 123n,
              },
              {
                kind: "mc",
                data: packPlanetMcMsg(
                  { cid: foreign ? "foreign" : cid, srcChanId: 123n, dstChanId: mediaChannel },
                  wrapMcMsg(
                    MC_MSG.NOTIFY_STRM_REQ,
                    new Uint8Array([10, 6, 8, state, 24, 31, 40, 42]),
                  ),
                ),
              },
            ),
            0x5100 + state,
          );
        let latestVideoSources: number[] = [];
        transport.onConference = (members) => {
          latestVideoSources = members.flatMap((m) =>
            m.sources.filter((s) => s.name === "V").map((s) => s.ssrc),
          );
        };
        incoming = notify(1, true);
        await new Promise((resolve) => setTimeout(resolve, 30));
        assertEquals(notifyAcks.length, 0);
        incoming = notify(1);
        await new Promise((resolve) => setTimeout(resolve, 30));
        assertEquals(latestVideoSources, [32]);
        assertEquals(notifyAcks[0]?.hdr?.msgId, 0x328f);
        assertEquals(notifyAcks[0]?.hdr?.tranId, new Uint8Array([2]));
        assertEquals(
          decodeFields(notifyAcks[0].mc!.bodyBytes!).map((f) => [f.tag, f.value]),
          [
            [1, 0n],
            [2, 0n],
          ],
        );
        const nextVideo = videoReceived.next();
        for (const ssrc of [31, 32]) {
          const part = packetizeSvcVp8(vp8, true, 2, 2, 2)[0];
          incoming = await srtpEncrypt(
            videoTx,
            buildRtp({
              payloadType: 97,
              ssrc,
              seq: 2,
              timestamp: 18000,
              marker: true,
              payload: part.payload,
              extensionProfile: 0x0240,
              extensionData: part.extensionData,
            }),
          );
          await new Promise((resolve) => setTimeout(resolve, 30));
        }
        assertEquals(
          (await withTimeout(nextVideo, 500, "unpaused participant continues")).value?.sourceMid,
          `u${"32".padStart(32, "0")}`,
        );
        incoming = notify(2);
        await new Promise((resolve) => setTimeout(resolve, 30));
        assertEquals(latestVideoSources, [31, 32]);
        assertEquals(subscriptions.length, 2); // Camera pause/resume does not resubscribe everyone.
        // A later channel unsubscribe must not be undone by an earlier NOTIFY channel hint.
        const leaveChannel = encodePb([
          {
            tag: 2,
            wireType: 2,
            value: encodePb([
              {
                tag: 2,
                wireType: 2,
                value: encodePb([
                  { tag: 1, wireType: 0, value: 2n },
                  { tag: 2, wireType: 0, value: 42n },
                  {
                    tag: 11,
                    wireType: 2,
                    value: encodePb([
                      {
                        tag: 1,
                        wireType: 2,
                        value: new TextEncoder().encode(`u${"31".padStart(32, "0")}`),
                      },
                      { tag: 3, wireType: 0, value: 0n },
                    ]),
                  },
                ]),
              },
            ]),
          },
        ]);
        incoming = await srtpEncrypt(
          await deriveSrtpContext(derivePlanetMediaStreamKeying(peerSecret, "DATA")),
          buildRtp({
            payloadType: 98,
            ssrc: 300,
            seq: 2,
            timestamp: 0,
            extensionProfile: 0x0240,
            payload: buildPdtp({
              number: 2n,
              service: "PLANET",
              sections: [
                {
                  type: 1,
                  body: new Uint8Array([
                    1,
                    1,
                    0x1e,
                    0,
                    0,
                    0,
                    0,
                    ...pdtpUint(BigInt(channel.length)),
                    ...pdtpUint(BigInt(leaveChannel.length)),
                    ...leaveChannel,
                  ]),
                },
              ],
            }),
          }),
        );
        await new Promise((resolve) => setTimeout(resolve, 30));
        assertEquals(subscriptions.length, 3);
        const stopped = decodeFields(
          decodeFields(subscriptions[2].mc!.bodyBytes!).find((f) => f.tag === 1)!
            .value as Uint8Array,
        );
        assertEquals(
          stopped.filter((f) => [1, 3, 7].includes(f.tag)).map((f) => [f.tag, f.value]),
          [
            [1, 0n],
            [3, 31n],
            [7, 42n],
          ],
        );
        for (const [source, foreign] of [
          [999, false],
          [213, true],
          [213, false],
        ] as const) {
          incoming = buildServerWire(
            serverKeys!,
            packPlanetMsg(
              {
                ...subscriptions[0].hdr!,
                msgId: 0x318d,
                tranId: new Uint8Array([44]),
                locNonce: 123n,
              },
              {
                kind: "mc",
                data: packPlanetMcMsg(
                  { cid: foreign ? "foreign" : cid, srcChanId: 123n, dstChanId: mediaChannel },
                  wrapMcMsg(
                    MC_MSG.STRM_REQ,
                    encodePb([
                      {
                        tag: 1,
                        wireType: 2,
                        value: encodePb([
                          { tag: 1, wireType: 0, value: 1n },
                          { tag: 3, wireType: 0, value: BigInt(source) },
                          { tag: 6, wireType: 0, value: 1n },
                          { tag: 8, wireType: 2, value: new Uint8Array([8, 2, 16, 1]) },
                        ]),
                      },
                    ]),
                  ),
                ),
              },
            ),
            0x5201,
          );
          await new Promise((resolve) => setTimeout(resolve, 30));
        }
        assertEquals(publisherAcks.length, 2);
        assertEquals(publisherAcks[1].hdr?.msgId, 0x328d);
        assertEquals(publisherAcks[1].hdr?.tranId, new Uint8Array([44]));
        assertEquals(publisherAcks[1].mc?.bodyBytes, new Uint8Array([8, 0, 16, 0]));
        // Receipt acknowledgement must never turn the user's camera on.
        await assertRejects(() => transport.sendVideo({ data: vp8, key: true, timestamp: 27000 }));
        await transport.setVideoEnabled(true);
        await transport.sendVideo({ data: vp8, key: true, timestamp: 27000 });
        const selectedCodec = parseRtp(await srtpDecrypt(videoRx, mediaWire.pop()!.packet));
        assertEquals(selectedCodec.payload[parseEvs3(selectedCodec.payload, true).offset], 4); // Request codecid1 selects VP8A framing.
        assertEquals(
          new Evs3Assembler().push({
            ...selectedCodec,
            payload: unwrapSvcVp8(selectedCodec.payload),
          })?.data,
          vp8,
        );
        await transport.setVideoEnabled(false);
        await videoReceived.return?.();
        await transport.close();
        assertEquals((await pendingAudio).done, true);
        return;
      }
      const local = transport.localMediaOffer!;
      assertEquals(local.offer, offered);
      assertEquals(transport.audioProfile?.frameDurationMs, 20);
      const rx = await deriveSrtpContext(
        derivePlanetMediaStreamKeying(local.material.mediaSecret, "AUDIO"),
      );
      for (let i = 0; i < 10; i++)
        await transport.send(new Uint8Array([0xf8, 0xff, 0xfd]), { audioLevel: 57 });
      assertEquals(mediaWire.length, 5); // no recorded DATA / RTCP replay
      for (const [index, wire] of mediaWire.entries()) {
        const rtp = parseRtp(await srtpDecrypt(rx, wire.packet));
        assertEquals(rtp.ssrc, 203); // Group answer assigns this TX SSRC.
        assertEquals(rtp.extensionData, new Uint8Array([1, 2, 0xc0, 0x68, 57, 0, 0, 0]));
        assertEquals(wire.port, 12345);
        assertEquals(rtp.timestamp, (index + 1) * 1920);
        assertEquals(depacketizeEas2(rtp.payload), [
          new Uint8Array([0xf8, 0xff, 0xfd]),
          new Uint8Array([0xf8, 0xff, 0xfd]),
        ]);
      }
      const received = transport.receiveAudio()[Symbol.asyncIterator]();
      if (outcome === "accepted-data") {
        const waiting = received.next();
        await withTimeout(dataSeen, 500, "authenticated group DATA");
        const dataRx = await deriveSrtpContext(
          derivePlanetMediaStreamKeying(local.material.mediaSecret, "DATA"),
        );
        assertEquals(mediaWire.length, 7);
        const ack = parseRtp(await srtpDecrypt(dataRx, mediaWire[5].packet));
        assertEquals([ack.payloadType, ack.ssrc, ack.seq], [98, 223, 1]);
        assertEquals([...ack.payload], [0x80, 0, 0, 0x40, 0, 4, 1, 3, 0, 0]);
        await transport.close();
        assertEquals((await waiting).done, true);
        return;
      }
      for (const ssrc of [11, 22]) {
        const next = await withTimeout(received.next(), 500, "group audio");
        assertEquals(next.value, {
          ssrc,
          timestamp: 960,
          frames: [new Uint8Array([0xf8, 0xff, 0xfd])],
        });
      }
      if (outcome === "remote-end") {
        releaseNow = true;
        assertEquals(
          (await withTimeout(received.next(), 500, "group release ends media")).done,
          true,
        );
        assertEquals(transport.remoteEnded, true);
        assertEquals((await transport.receiveAudio()[Symbol.asyncIterator]().next()).done, true);
      }
      await received.return?.();
    } finally {
      await transport.close();
      await transport.close();
      assertEquals(
        releases.map((r) => [r.releaser, r.roomDestroy]),
        outcome === "remote-end" ? [] : [["participant", false]],
      );
    }
  });
}

Deno.test("group control scopes PUSH/REL to negotiated CID, updates roster and acknowledges transactions", async () => {
  const peer = generateEphemeralKeypair();
  const seed = new Uint8Array(16).fill(8);
  const cid = "negotiated-group";
  const mid = `u${"1".repeat(32)}`;
  const controls: Uint8Array[] = [];
  const replies: ReturnType<typeof decodePlanetMsg>[] = [];
  const rosters: string[][] = [];
  let releaseNow = false;
  const transport = new PlanetTransport({
    localMid: "u-local",
    callId: "requested-group",
    timeoutMs: 500,
    keepaliveIntervalMs: 10,
    wireSend(packet, endpoint) {
      if (
        isRtpLike(packet) ||
        endpoint.plaintext.length === 519 ||
        endpoint.plaintext.length === 10
      )
        return;
      const msg = decodePlanetMsg(endpoint.plaintext);
      if (msg.hdr?.msgId === 0x1101) return releaseNow ? controls.shift() : undefined;
      if (msg.cc?.bodyTag !== CC_MSG.PARTICIPATE_REQ) {
        if (msg.cc) replies.push(msg);
        return;
      }
      const keys = deriveCallKeys({
        mpkey: extractBootstrapClientPub(packet),
        local: peer,
        bootstrapSeed: seed,
        sendLabel: 0x3456,
        recvLabel: 0x3456,
      }).send;
      let seq = 0x5001;
      const control = (bodyTag: number, bodyBytes: Uint8Array, msgId: number, call = cid) =>
        buildServerWire(
          keys,
          buildControlPlain({
            bodyTag,
            bodyBytes,
            msgId,
            sessId: seed,
            locNonce: 123n,
            cid: call,
            srcChanId: 123n,
          }),
          seq++,
        );
      const push = (connected: boolean, version: number) =>
        encodePb([
          { tag: 1, wireType: 0, value: 1n },
          {
            tag: 2,
            wireType: 2,
            value: encodePb([
              { tag: 1, wireType: 0, value: 0n },
              { tag: 2, wireType: 0, value: BigInt(version) },
              {
                tag: 50,
                wireType: 2,
                value: encodePb([
                  { tag: 1, wireType: 2, value: new TextEncoder().encode(mid) },
                  { tag: 3, wireType: 0, value: connected ? 1n : 0n },
                ]),
              },
            ]),
          },
        ]);
      const rel = packCcRelReq({ relCode: 2, roomDestroy: false });
      controls.push(
        control(CC_MSG.REL_REQ, rel, 0x2145, "unrelated-call"),
        control(CC_MSG.PUSH_REQ, push(true, 99), 0x2150, "unrelated-call"),
        control(CC_MSG.PUSH_REQ, push(true, 1), 0x2150),
        control(CC_MSG.PUSH_REQ, push(false, 2), 0x2150),
        control(CC_MSG.REL_REQ, rel, 0x2145),
      );
      return buildServerWire(
        keys,
        buildControlPlain({
          bodyTag: CC_MSG.PARTICIPATE_RSP,
          bodyBytes: encodePb([
            { tag: 1, wireType: 0, value: 0n },
            {
              tag: 6,
              wireType: 2,
              value: packNativeGroupParticipateOffer({ mediaSecret: new Uint8Array(30).fill(7) }),
            },
            { tag: 7, wireType: 0, value: 123n },
          ]),
          msgId: 0x2261,
          sessId: seed,
          locNonce: 123n,
          cid,
          srcChanId: 123n,
        }),
        seq++,
        { bootstrap: { label: 0x3456, seed, pub: peer.publicKey } },
      );
    },
  });
  transport.onConference = (members) => rosters.push(members.map((m) => m.mid));
  await transport.connect({
    route: {
      voipAddress: "127.0.0.1",
      voipUdpPort: 9,
      commParam: JSON.stringify({ mpkey: bytesToBase64(peer.publicKey) }),
      token: "test-token",
      hostMid: "u-local",
    } as CallRouteLike,
  });
  try {
    await transport.joinGroupDetailed({ roomId: "c-room" });
    releaseNow = true;
    const received = transport.receiveAudio()[Symbol.asyncIterator]();
    assertEquals((await withTimeout(received.next(), 1000, "scoped group release")).done, true);
    assertEquals(rosters, [[mid], []]);
    assertEquals(controls.length, 0);
    assertEquals(
      replies.map((m) => [m.cc?.bodyTag, m.hdr?.msgId]),
      [
        [CC_MSG.PUSH_RSP, 0x2250],
        [CC_MSG.PUSH_RSP, 0x2250],
        [CC_MSG.REL_RSP, 0x2245],
      ],
    );
    for (const reply of replies) {
      assertEquals(reply.cc?.hdr?.cid, cid);
      assertEquals(reply.cc?.hdr?.dstChanId, 123n);
      assertEquals(decodeFields(reply.cc!.bodyBytes!)[0].value, 0n);
      const requestId = reply.cc?.bodyTag === CC_MSG.REL_RSP ? 0x2145 : 0x2150;
      assertEquals(reply.hdr?.tranId, new Uint8Array(16).fill(requestId & 255));
      assertEquals(reply.hdr?.rmtNonce, 123n);
    }
  } finally {
    await transport.close();
  }
});

Deno.test("Group DATA learns its media endpoint only after SRTP authentication", async () => {
  const server = await bindUdpServer();
  const mediaServer = await bindUdpServer();
  const peer = generateEphemeralKeypair();
  const secret = new Uint8Array(30).fill(7);
  const seed = new Uint8Array(16).fill(8);
  let client: RemoteInfo | undefined;
  let error: unknown;
  let resolveAck!: (wire: Uint8Array) => void;
  const ack = new Promise<Uint8Array>((resolve) => {
    resolveAck = resolve;
  });
  mediaServer.on("message", (wire) => resolveAck(new Uint8Array(wire)));
  server.on("message", (buf, rinfo) => {
    if (client) return;
    client = rinfo;
    try {
      const wire = new Uint8Array(buf);
      const keys = deriveCallKeys({
        mpkey: extractBootstrapClientPub(wire),
        local: peer,
        bootstrapSeed: seed,
        sendLabel: 0x3456,
        recvLabel: 0x3456,
      }).send;
      const body = encodePb([
        { tag: 1, wireType: 0, value: 0n },
        { tag: 6, wireType: 2, value: packNativeGroupParticipateOffer({ mediaSecret: secret }) },
        { tag: 7, wireType: 0, value: 123n },
        {
          tag: 101,
          wireType: 2,
          value: encodePb([
            {
              tag: 1,
              wireType: 2,
              value: packPlanetAddr({
                ip: "127.0.0.1",
                port: (server.address() as { port: number }).port,
              }),
            },
          ]),
        },
      ]);
      void sendUdp(
        server,
        buildServerWire(
          keys,
          buildControlPlain({
            bodyTag: CC_MSG.PARTICIPATE_RSP,
            bodyBytes: body,
            msgId: 0x2261,
            sessId: seed,
            locNonce: 123n,
            cid: "test-group",
            srcChanId: 123n,
          }),
          0x5001,
          { bootstrap: { label: 0x3456, seed, pub: peer.publicKey } },
        ),
        rinfo,
      );
    } catch (e) {
      error = e;
    }
  });
  const transport = new PlanetTransport({
    localMid: "u-local",
    timeoutMs: 500,
    keepaliveIntervalMs: 0,
  });
  let receiver: Promise<IteratorResult<unknown>> | undefined;
  try {
    await transport.connect({
      route: {
        voipAddress: "127.0.0.1",
        voipUdpPort: (server.address() as { port: number }).port,
        commParam: JSON.stringify({ mpkey: bytesToBase64(peer.publicKey) }),
        token: "test-token",
        hostMid: "u-local",
      } as CallRouteLike,
    });
    await transport.joinGroup({ roomId: "c-room" });
    if (error) throw error;
    assert(client);
    receiver = transport.receiveAudio()[Symbol.asyncIterator]().next();
    const rtp = buildRtp({
      payloadType: 98,
      ssrc: 123,
      seq: 1,
      timestamp: 0,
      payload: new Uint8Array([
        0x80,
        0,
        ...new TextEncoder().encode("PLANET"),
        0,
        0,
        8,
        4,
        1,
        1,
        0x12,
        0,
      ]),
      extensionProfile: 0x0240,
    });
    await sendUdp(
      mediaServer,
      await srtpEncrypt(await deriveSrtpContext(new Uint8Array(30)), rtp),
      client,
    );
    await sendUdp(
      mediaServer,
      await srtpEncrypt(
        await deriveSrtpContext(derivePlanetMediaStreamKeying(secret, "DATA")),
        rtp,
      ),
      client,
    );
    const response = await withTimeout(ack, 500, "group ACK sent to authenticated media source");
    const rx = await deriveSrtpContext(
      derivePlanetMediaStreamKeying(transport.localMediaOffer!.material.mediaSecret, "DATA"),
    );
    assertEquals(parseRtp(await srtpDecrypt(rx, response)).payloadType, 98);
  } finally {
    await transport.close();
    await receiver;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await new Promise<void>((resolve) => mediaServer.close(() => resolve()));
  }
});

async function testIncomingAnswer(peerSecurity: "both" | "simple" | "none") {
  const routePeer = generateEphemeralKeypair();
  const peerMedia = generateEphemeralKeypair();
  const peerOffer =
    peerSecurity === "none"
      ? new Uint8Array(0)
      : peerSecurity === "simple"
        ? packNativeGroupParticipateOffer({ mediaSecret: new Uint8Array(30).fill(0x55) })
        : packNativeSetupOffer({
            mediaPubKey: peerMedia.publicKey,
            mediaKeyId: 0x12345678,
            mediaNonce: new Uint8Array(16).fill(0x44),
            mediaSecret: new Uint8Array(30).fill(0x55),
          });
  const route = makeRoute(routePeer);
  // Android 26.13.0 passes incoming JSON `vs` (voipSessionId) to native as
  // CallSession.InitiatorInfo.communicationId; Planet uses that value as CID.
  const cid = String(route.stid);
  const replySeed = new Uint8Array(16).fill(0x61);
  const replyLabel = 0x3456;
  const sessId = new Uint8Array(16).fill(0x62);
  let serverSendKeys: TransportKeys | undefined;
  let advertisedDeviceId: string | undefined;
  let sentAudioSsrc: number | undefined;
  const sentCcTags: number[] = [];
  const sentMsgIds: number[] = [];
  const debugEvents: Record<string, unknown>[] = [];
  const customDeviceId = bytesToBase64(new Uint8Array(32).fill(0x5a));

  const verifyRspPlain = buildControlPlain({
    bodyTag: CC_MSG.VERIFY_RSP,
    bodyBytes: packCcVerifyRsp({
      result: 0,
      oCapas: [1, 2, 7],
      offer: peerOffer,
      oFeatures: [],
      iDevId: bytesToBase64(new Uint8Array(32)),
    }),
    msgId: 0x2242,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x1001n,
  });
  const connRspPlain = buildControlPlain({
    bodyTag: CC_MSG.CONN_RSP,
    bodyBytes: packCcConnRsp({ result: 0, mChanId: 0x3003n, netType: 1, unavailToSec: 120 }),
    msgId: 0x2244,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x1001n,
  });

  const transport = new PlanetTransport({
    localMid: "u-local",
    callId: cid,
    deviceId: customDeviceId,
    userAgent: {
      osName: "Custom OS",
      osVersion: "1",
      deviceName: "Custom device",
      kitWrapperVersion: "custom-wrapper",
    },
    timeoutMs: 500,
    debug: (event) => debugEvents.push(event),
    wireSend(packet, endpoint) {
      if (endpoint.plaintext.length === 4 && endpoint.plaintext[0] === 0x10) {
        sentAudioSsrc = parseRtp(packet).ssrc;
        return;
      }
      if (endpoint.plaintext.length === 519 || endpoint.plaintext.length === 10) return;
      let msg: ReturnType<typeof decodePlanetMsg>;
      try {
        msg = decodePlanetMsg(endpoint.plaintext);
      } catch {
        return;
      }
      if (msg.cc?.bodyTag !== undefined) {
        sentCcTags.push(msg.cc.bodyTag);
        sentMsgIds.push(msg.hdr?.msgId ?? 0);
      }
      if (msg.cc?.bodyTag === CC_MSG.VERIFY_REQ) {
        assertEquals(msg.cc.hdr?.cid, cid);
        const clientPub = extractBootstrapClientPub(packet);
        const clientLabel = extractBootstrapClientLabel(packet);
        const clientSeed = extractBootstrapClientSeed(packet);
        // Verify that the first control packet is the responder VERIFY bootstrap,
        // never the outgoing caller SETUP_REQ.
        assertEquals(endpoint.bootstrap, true);
        const verifyFields = decodeFields(msg.cc.bodyBytes!);
        assertEquals(
          new TextDecoder().decode(verifyFields.find((f) => f.tag === 1)!.value as Uint8Array),
          "u-peer",
        );
        assertEquals(
          new TextDecoder().decode(verifyFields.find((f) => f.tag === 2)!.value as Uint8Array),
          "u-local",
        );
        const advertisedUa = verifyFields.find((f) => f.tag === 5)!.value as Uint8Array;
        assertEquals(
          new TextDecoder().decode(
            decodeFields(advertisedUa).find((f) => f.tag === 9)!.value as Uint8Array,
          ),
          "custom-wrapper",
        );
        advertisedDeviceId = new TextDecoder().decode(
          verifyFields.find((f) => f.tag === 6)!.value as Uint8Array,
        );
        const decodedDeviceId = Uint8Array.from(atob(advertisedDeviceId), (char) =>
          char.charCodeAt(0),
        );
        assertEquals(decodedDeviceId.length, 32);
        assertEquals(advertisedDeviceId, customDeviceId);
        serverSendKeys = deriveCallKeys({
          mpkey: clientPub,
          local: routePeer,
          bootstrapSeed: replySeed,
          sendLabel: replyLabel,
          recvLabel: replyLabel,
        }).send;
        // Deriving the client receive-side counterpart also proves the bootstrap
        // values are structurally valid for this route.
        deriveCallKeys({
          mpkey: clientPub,
          local: routePeer,
          bootstrapSeed: clientSeed,
          sendLabel: clientLabel,
          recvLabel: clientLabel,
        });
        return buildServerWire(serverSendKeys, verifyRspPlain, 0x5101, {
          bootstrap: { label: replyLabel, seed: replySeed, pub: routePeer.publicKey },
        });
      }
      if (msg.cc?.bodyTag === CC_MSG.CONN_REQ) {
        assert(serverSendKeys);
        assertEquals(endpoint.bootstrap, false);
        const conn = decodeCcConnReq(msg.cc.bodyBytes!);
        assert(conn.answer && conn.answer.length > 0);
        // Native rejects all session crypto when an answer contains >1 scheme.
        const security = decodeFields(conn.answer).filter((field) => field.tag === 2);
        assertEquals(security.length, 1);
        assertEquals(
          decodeFields(security[0].value as Uint8Array)[0].tag,
          peerSecurity === "both" ? 3 : 2,
        );
        if (peerSecurity === "both") assertEquals(conn.answer.length, 275);
        assertEquals(conn.mChanId !== undefined, true);
        assertEquals(conn.devId, advertisedDeviceId);
        return buildServerWire(serverSendKeys, connRspPlain, 0x5102);
      }
    },
  });

  await transport.connect({ route });
  if (peerSecurity === "none") {
    await assertRejects(() => transport.answer(), Error, "no supported encrypted media scheme");
    await transport.close();
    assertEquals(sentCcTags.includes(CC_MSG.CONN_REQ), false);
    return;
  }
  const result = await transport.answer();
  assert(result.mediaReady);
  assertEquals(result.connRsp.result, 0);
  assertEquals(sentCcTags[0], CC_MSG.VERIFY_REQ);
  assertEquals(sentCcTags.includes(CC_MSG.SETUP_REQ), false);
  assertEquals(sentCcTags.includes(CC_MSG.CONN_REQ), true);
  assertEquals(sentMsgIds.slice(0, 2), [0x2142, 0x2144]);
  await transport.send(new Uint8Array([0xf8, 0xff, 0xfd]));
  assertEquals(sentAudioSsrc, 101);
  await transport.close();
}

Deno.test("PlanetTransport.answer prefers one E2EE scheme and its advertised RX stream", () =>
  testIncomingAnswer("both"));
Deno.test("PlanetTransport.answer selects one SRTP scheme for a simple-only peer", () =>
  testIncomingAnswer("simple"));
Deno.test("PlanetTransport.answer refuses a peer offering no encrypted media", () =>
  testIncomingAnswer("none"));

async function testPeerAudio(peerSecurity: "ecdh" | "simple" | "simple-only", video = false) {
  const routePeer = generateEphemeralKeypair();
  const server = await bindUdpServer();
  const mediaServer = await bindUdpServer();
  const debugEvents: Record<string, unknown>[] = [];
  const addr = server.address();
  const mediaAddr = mediaServer.address();
  const port = typeof addr === "string" ? 0 : addr.port;
  const mediaPort = typeof mediaAddr === "string" ? 0 : mediaAddr.port;
  const route = makeRoute(routePeer, port);
  const transport = new PlanetTransport({
    localMid: "u-local",
    timeoutMs: 1000,
    keepaliveIntervalMs: 20,
    debug: (event) => debugEvents.push(event),
  });

  const peerMedia = generateEphemeralKeypair();
  const peerMaterial: PlanetSetupOfferMaterial = {
    mediaPubKey: peerMedia.publicKey,
    mediaKeyId: 0x33445566,
    mediaNonce: new Uint8Array(16).fill(0x23),
    mediaSecret: new Uint8Array(30).fill(0x42),
  };
  const sessId = new Uint8Array(16).fill(0x7a);
  const replySeed = new Uint8Array(16).fill(0x34);
  const replyLabel = 0x4567;
  const cid = "test-call";
  const setupRspPlain = buildControlPlain({
    bodyTag: CC_MSG.SETUP_RSP,
    bodyBytes: packCcSetupRsp({
      result: 0,
      aliveRptInterval: 5,
      noAnsToSec: 30,
    }),
    msgId: 1,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x1001n,
  });
  const connReqPlain = buildControlPlain({
    bodyTag: CC_MSG.CONN_REQ,
    bodyBytes: packCcConnReq({
      answer:
        peerSecurity === "simple-only"
          ? packNativeGroupParticipateOffer({ mediaSecret: peerMaterial.mediaSecret })
          : packNativeSetupOffer(peerMaterial, undefined, video ? { enabled: true } : undefined),
      mChanId: 0x2002n,
      netType: 1,
      unavailToSec: 120,
      oCapas: [1, 2, 3],
      features: [],
      ua: packPlanetUserAgent({
        osName: "Android",
        osVersion: "36",
        deviceName: "Android",
        kitWrapperVersion: "native-wrapper",
      }),
    }),
    msgId: 2,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x1001n,
    dstChanId: 0x2002n,
  });
  const infoReqPlain = buildControlPlain({
    bodyTag: CC_MSG.INFO_REQ,
    bodyBytes: packCcInfoReq({
      bodyType: "profile",
      body: new Uint8Array([1, 2, 3]),
      targets: ["u-local"],
      source: "u-peer",
      sourceSvcId: "freecall.audio",
      tgtUe: [],
    }),
    msgId: 3,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x1001n,
    dstChanId: 0x2002n,
  });
  const mcDataReqPlain = buildMediaControlPlain({
    bodyTag: MC_MSG.DATA_REQ,
    bodyBytes: packMcDataReq({
      srcType: 0,
      dstType: 0,
      dispatchId: 2,
      data: new Uint8Array([0]),
    }),
    msgId: 0x3189,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x2002n,
    dstChanId: 0x3003n,
  });

  let setupHandled = false;
  let clientRinfo: RemoteInfo | undefined;
  let serverRecvKeys: TransportKeys | undefined;
  let controlSendKeys: TransportKeys | undefined;
  let serverMessages = 0;
  let serverError: unknown;
  let connReqWireForRetry: Uint8Array | undefined;
  let connRspCount = 0;
  const videoControls: unknown[] = [];
  const pinholePlainLengths: number[] = [];
  let resolveMedia!: (packet: Uint8Array) => void;
  let resolvePinholeReport!: () => void;
  let resolveSecondConnRsp!: (hdr?: DecodedPlanetMsgHdr) => void;
  let resolveInfoReq!: (bodyTag: number) => void;
  let resolveInfoRsp!: (bodyTag: number) => void;
  let resolveMcDataRsp!: (rsp: {
    dispatchId: number;
    dataLength: number;
    bodyLength: number;
  }) => void;
  let resolveRelReq!: (req: { bodyTag: number; dstChanId: string }) => void;
  let resolveKeepalive!: (bodyTag: number) => void;
  const mediaPackets: Uint8Array[] = [];
  const mediaWaiters: Array<(buf: Uint8Array) => void> = [];
  const getMediaWire = (): Promise<Uint8Array> => {
    const queued = mediaPackets.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((res) => mediaWaiters.push(res));
  };
  const pinholeReport = new Promise<void>((resolve) => {
    resolvePinholeReport = resolve;
  });
  const secondConnRsp = new Promise<DecodedPlanetMsgHdr | undefined>((resolve) => {
    resolveSecondConnRsp = resolve;
  });
  const infoReq = new Promise<number>((resolve) => {
    resolveInfoReq = resolve;
  });
  const infoRsp = new Promise<number>((resolve) => {
    resolveInfoRsp = resolve;
  });
  const mcDataRsp = new Promise<{ dispatchId: number; dataLength: number; bodyLength: number }>(
    (resolve) => {
      resolveMcDataRsp = resolve;
    },
  );
  const relReq = new Promise<{ bodyTag: number; dstChanId: string }>((resolve) => {
    resolveRelReq = resolve;
  });
  const keepalive = new Promise<number>((resolve) => {
    resolveKeepalive = resolve;
  });
  mediaServer.on("message", (buf: Buffer) => {
    const arr = new Uint8Array(buf);
    const waiter = mediaWaiters.shift();
    if (waiter) waiter(arr);
    else mediaPackets.push(arr);
  });
  server.on("message", (buf: Buffer, rinfo: RemoteInfo) => {
    try {
      clientRinfo = rinfo;
      serverMessages++;
      const wire = new Uint8Array(buf);
      if (isRtpLike(wire)) {
        serverError = new Error("media packet was sent to signaling socket");
        return;
      }
      if (setupHandled && serverRecvKeys) {
        const plain = decryptRegularWire(serverRecvKeys, wire);
        if (!plain) return;
        if (plain.length === 519 || plain.length === 10) {
          pinholePlainLengths.push(plain.length);
          if (plain.length === 10) resolvePinholeReport();
          return;
        }
        const msg = decodePlanetMsg(plain);
        if (msg.mc?.bodyTag === MC_MSG.DATA_REQ && msg.mc.bodyBytes) {
          const req = decodeMcDataReq(msg.mc.bodyBytes);
          if (req.data) videoControls.push(decodeMcStreamControl(req.data));
          if (controlSendKeys && req.data) {
            const response = packPlanetMsg(
              { ...msg.hdr!, userId: "u-server", locNonce: 0x123456n, msgId: 0x3289 },
              {
                kind: "mc",
                data: packPlanetMcMsg(
                  { cid, srcChanId: 0x3003n, dstChanId: msg.mc.hdr?.srcChanId },
                  wrapMcMsg(
                    MC_MSG.DATA_RSP,
                    packMcDataRsp({ result: 0, relCode: 0, dispatchId: 2, data: req.data }),
                  ),
                ),
              },
            );
            void sendUdp(
              server,
              buildServerWire(controlSendKeys, response, 0x6100 + videoControls.length),
              rinfo,
            );
          }
        }
        if (msg.cc?.bodyTag === CC_MSG.CONN_RSP) {
          connRspCount++;
          if (connRspCount >= 2) resolveSecondConnRsp(msg.hdr);
        }
        if (msg.cc?.bodyTag === CC_MSG.INFO_REQ) {
          resolveInfoReq(msg.cc.bodyTag);
        }
        if (msg.cc?.bodyTag === CC_MSG.INFO_RSP) {
          resolveInfoRsp(msg.cc.bodyTag);
        }
        if (msg.cc?.bodyTag === CC_MSG.REL_REQ) {
          resolveRelReq({
            bodyTag: msg.cc.bodyTag,
            dstChanId: String(msg.cc.hdr?.dstChanId ?? 0n),
          });
        }
        if (msg.mc?.bodyTag === MC_MSG.DATA_RSP && msg.mc.bodyBytes) {
          const rsp = decodeMcDataRsp(msg.mc.bodyBytes);
          const data = rsp.data ?? new Uint8Array();
          resolveMcDataRsp({
            dispatchId: rsp.dispatchId ?? 0,
            dataLength: data.length,
            bodyLength: data.length >= 6 ? (data[4] << 8) | data[5] : 0,
          });
        }
        if (msg.scBytes) {
          resolveKeepalive(decodeFields(msg.scBytes)[0]?.tag ?? 0);
        }
        return;
      }
      if (setupHandled) return;
      setupHandled = true;
      const clientPub = extractBootstrapClientPub(wire);
      const clientLabel = extractBootstrapClientLabel(wire);
      const clientSeed = extractBootstrapClientSeed(wire);
      const serverKeys = deriveCallKeys({
        mpkey: clientPub,
        local: routePeer,
        bootstrapSeed: replySeed,
        sendLabel: replyLabel,
        recvLabel: replyLabel,
      }).send;
      controlSendKeys = serverKeys;
      serverRecvKeys = deriveCallKeys({
        mpkey: clientPub,
        local: routePeer,
        bootstrapSeed: clientSeed,
        sendLabel: clientLabel,
        recvLabel: clientLabel,
      }).recv;
      const setupRspWire = buildServerWire(serverKeys, setupRspPlain, 0x5101, {
        bootstrap: {
          label: replyLabel,
          seed: replySeed,
          pub: routePeer.publicKey,
        },
      });
      const connReqWire = buildServerWire(serverKeys, connReqPlain, 0x5102);
      connReqWireForRetry = connReqWire;
      const infoReqWire = buildServerWire(serverKeys, infoReqPlain, 0x5103);
      const mcDataReqWire = buildServerWire(serverKeys, mcDataReqPlain, 0x5104);
      void sendUdp(server, setupRspWire, rinfo)
        .then(() => new Promise((resolve) => setTimeout(resolve, 5)))
        .then(() => sendUdp(server, connReqWire, rinfo))
        .then(() => new Promise((resolve) => setTimeout(resolve, 5)))
        .then(() => sendUdp(server, infoReqWire, rinfo))
        .then(() => new Promise((resolve) => setTimeout(resolve, 5)))
        .then(() => sendUdp(server, mcDataReqWire, rinfo));
    } catch (e) {
      serverError = e;
    }
  });

  let transportClosed = false;
  try {
    await transport.connect({ route });
    const invite = await transport.inviteDetailed({ to: "u-peer" }).catch((e) => {
      throw new Error(
        `invite failed after ${serverMessages} server messages: ${
          serverError instanceof Error ? serverError.message : String(serverError ?? e)
        }`,
      );
    });
    assertEquals(invite.setupRsp?.result, 0);
    const answer = await transport.waitForAnswerDetailed({ timeoutMs: 1000 });
    assert(answer.mediaReady);
    assertEquals(answer.connRspSent, true);
    await withTimeout(pinholeReport, 1000, "pinhole_report");
    assertEquals(pinholePlainLengths.filter((len) => len === 519).length, 16);
    assertEquals(pinholePlainLengths.filter((len) => len === 10).length, 1);
    assertEquals(await withTimeout(infoReq, 1000, "info_req"), CC_MSG.INFO_REQ);
    assertEquals(await withTimeout(infoRsp, 1000, "info_rsp"), CC_MSG.INFO_RSP);
    assertEquals(await withTimeout(mcDataRsp, 1000, "mc_data_rsp"), {
      dispatchId: 2,
      dataLength: 148,
      bodyLength: 139,
    });
    assertEquals(await withTimeout(keepalive, 1000, "keepalive"), 1);
    assert(clientRinfo);
    await sendUdp(server, connReqWireForRetry, clientRinfo);
    const secondRspHdr = await withTimeout(secondConnRsp, 1000, "duplicate_conn_rsp");
    assert(secondRspHdr?.tranId);
    const expectedTranId = new Uint8Array(16);
    expectedTranId.fill(2); // msgId: 2 in buildControlPlain for connReqPlain
    assertEquals(secondRspHdr.tranId, expectedTranId);
    assertEquals(secondRspHdr.rmtNonce, 0x123456n);
    await sendUdp(
      mediaServer,
      new Uint8Array([0x80, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]),
      clientRinfo,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    assertEquals(debugEvents.filter((event) => event.type === "media_endpoint_learned").length, 0);

    const localMedia = transport.localMediaOffer;
    assert(localMedia);
    const peerKeys = derivePlanetMediaKeys({
      local: {
        privateKey: peerMedia.privateKey,
        publicKey: peerMaterial.mediaPubKey,
        mediaKeyId: peerMaterial.mediaKeyId,
        mediaNonce: peerMaterial.mediaNonce,
      },
      peer: {
        publicKey: localMedia.material.mediaPubKey,
        mediaKeyId: localMedia.material.mediaKeyId,
        mediaNonce: localMedia.material.mediaNonce,
      },
    });
    const peerRecv = await deriveSrtpContext(
      derivePlanetMediaStreamKeying(
        peerSecurity === "ecdh" ? peerKeys.sendKeying : localMedia.material.mediaSecret,
        "AUDIO",
      ),
    );
    const peerSend = await deriveSrtpContext(
      derivePlanetMediaStreamKeying(
        peerSecurity === "ecdh" ? peerKeys.recvKeying : peerMaterial.mediaSecret,
        "AUDIO",
      ),
    );
    const remoteOpus = new Uint8Array([0xf8, 0xff, 0xfd]);
    const remotePayload = new Uint8Array([0x70, 0xf9, 0xff, 0xfd]);
    const initialRemoteRtp = buildRtp({
      payloadType: 96,
      seq: 0x320e,
      timestamp: 960,
      ssrc: 0x10203040,
      payload: remotePayload,
    });
    const initialRemoteWire = await srtpEncrypt(peerSend, initialRemoteRtp);
    const initialReceivedAudio = transport.receive()[Symbol.asyncIterator]().next();
    await sendUdp(mediaServer, initialRemoteWire, clientRinfo);
    assertEquals(
      (await withTimeout(initialReceivedAudio, 1000, "initial remote audio")).value,
      remoteOpus,
    );
    assertEquals(debugEvents.filter((event) => event.type === "media_endpoint_learned").length, 1);
    assertEquals(
      debugEvents.filter((event) => event.type === "media_key_selected").map((event) => event.mode),
      peerSecurity === "simple" ? ["audio-secret-sender"] : [],
    );

    const unexpectedPayloadRtp = buildRtp({
      payloadType: 101,
      seq: 0x320f,
      timestamp: 0,
      ssrc: 0x10203040,
      payload: new Uint8Array([0x11, 0x22]),
    });
    await sendUdp(server, await srtpEncrypt(peerSend, unexpectedPayloadRtp), clientRinfo);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assertEquals(debugEvents.filter((event) => event.type === "media_endpoint_learned").length, 1);

    const opus = new Uint8Array([0xf8, 0xff, 0xfd]);
    await transport.send(opus);
    const receivedWire = await withTimeout(getMediaWire(), 1000, "media");
    const rtp = await srtpDecrypt(peerRecv, receivedWire);
    const sentRtp = parseRtp(rtp);
    assertEquals(sentRtp.payload, new Uint8Array([0x10, 0xf9, 0xff, 0xfd]));
    assertEquals(sentRtp.marker, true);
    assertEquals(sentRtp.timestamp, 960);

    // A continuous speech chunk keeps its id; marker is only set at its start.
    await transport.send(opus);
    const receivedWire2 = await withTimeout(getMediaWire(), 1000, "media2");
    const rtp2 = await srtpDecrypt(peerRecv, receivedWire2);
    const sentRtp2 = parseRtp(rtp2);
    assertEquals(sentRtp2.payload, new Uint8Array([0x10, 0xf9, 0xff, 0xfd]));
    assertEquals(sentRtp2.marker, false);
    assertEquals(sentRtp2.timestamp, 1920);

    const unrelatedRtp = buildRtp({
      payloadType: 101,
      seq: 0x320f,
      timestamp: 0,
      ssrc: 0x10203040,
      payload: new Uint8Array([0x11, 0x22]),
    });
    const unrelatedWire = await srtpEncrypt(peerSend, unrelatedRtp);
    // RTCP packet on same port (RFC 5761 multiplexing) — should be skipped cleanly
    const rtcpWire = new Uint8Array([0x80, 205, 0x00, 0x03, 0x10, 0x20, 0x30, 0x40, 0, 0, 0, 0]);
    const remoteRtp = buildRtp({
      payloadType: 96,
      seq: 0x3210,
      timestamp: 960,
      ssrc: 0x10203040,
      payload: remotePayload,
    });
    const remoteWire = await srtpEncrypt(peerSend, remoteRtp);
    const receivedAudio = transport.receive()[Symbol.asyncIterator]().next();
    await sendUdp(mediaServer, unrelatedWire, clientRinfo);
    await sendUdp(mediaServer, rtcpWire, clientRinfo);
    await sendUdp(mediaServer, remoteWire, clientRinfo);
    const remotePacket = await withTimeout(receivedAudio, 1000, "remote audio");
    assertEquals(remotePacket.value, remoteOpus);
    if (video) {
      assertEquals(transport.videoAvailable, true);
      const vp8 = new Uint8Array([0x30, 0, 0, 0x9d, 1, 0x2a, 0x80, 2, 0x68, 1, 0, 0]);
      const peerVideoRecv = await deriveSrtpContext(
        derivePlanetMediaStreamKeying(
          peerSecurity === "ecdh" ? peerKeys.sendKeying : localMedia.material.mediaSecret,
          "VIDEO",
        ),
      );
      const peerVideoSend = await deriveSrtpContext(
        derivePlanetMediaStreamKeying(
          peerSecurity === "ecdh" ? peerKeys.recvKeying : peerMaterial.mediaSecret,
          "VIDEO",
        ),
      );
      await transport.setVideoEnabled(true);
      await transport.sendVideo({ data: vp8, key: true, timestamp: 9000 });
      const sentVideo = parseRtp(
        await srtpDecrypt(peerVideoRecv, await withTimeout(getMediaWire(), 1000, "video send")),
      );
      assertEquals([sentVideo.payloadType, sentVideo.ssrc, sentVideo.timestamp], [97, 211, 9000]);
      assertEquals(new Evs3Assembler().push(sentVideo)?.data, vp8);
      const videoIterator = transport.receiveVideo()[Symbol.asyncIterator]();
      const gotVideo = videoIterator.next();
      const simultaneousAudio = transport.receive()[Symbol.asyncIterator]().next();
      const incomingVideo = buildRtp({
        payloadType: 97,
        ssrc: 111,
        seq: 20,
        timestamp: 9000,
        marker: true,
        payload: packetizeEvs3(vp8, true, 1)[0],
      });
      const wrongKeyVideo = await srtpEncrypt(peerSend, incomingVideo);
      await sendUdp(mediaServer, wrongKeyVideo, clientRinfo);
      await sendUdp(mediaServer, await srtpEncrypt(peerVideoSend, incomingVideo), clientRinfo);
      await sendUdp(mediaServer, remoteWire, clientRinfo);
      assertEquals((await withTimeout(gotVideo, 1000, "video receive")).value?.data, vp8);
      assertEquals(
        (await withTimeout(simultaneousAudio, 1000, "audio while video")).value,
        remoteOpus,
      );
      await transport.setVideoEnabled(false);
      await assertRejects(
        () => transport.sendVideo({ data: vp8, key: true, timestamp: 12000 }),
        Error,
        "not enabled",
      );
      await new Promise((resolve) => setTimeout(resolve, 10));
      assertEquals(videoControls, [
        { operation: 1, mediaKind: 2, code: 0, ssrcs: [211, 111] },
        { operation: 3, mediaKind: 2, code: 0, ssrcs: [211] },
      ]);
      const closing = videoIterator.next();
      await transport.close();
      assertEquals((await withTimeout(closing, 1000, "video cleanup")).done, true);
      transportClosed = true;
    }
    if (!transportClosed) await transport.close();
    transportClosed = true;
    assertEquals(await withTimeout(relReq, 1000, "rel_req"), {
      bodyTag: CC_MSG.REL_REQ,
      dstChanId: String(0x1001n),
    });
  } finally {
    if (!transportClosed) await transport.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await new Promise<void>((resolve) => mediaServer.close(() => resolve()));
  }
}

Deno.test("PlanetTransport authenticates ECDH audio before selecting keys and endpoint", () =>
  testPeerAudio("ecdh"));
Deno.test("PlanetTransport authenticates simple audio before selecting keys and endpoint", () =>
  testPeerAudio("simple"));
Deno.test("PlanetTransport supports a peer selecting only the simple security scheme", () =>
  testPeerAudio("simple-only"));
Deno.test("PlanetTransport upgrades encrypted ECDH video without disrupting audio", () =>
  testPeerAudio("ecdh", true));
Deno.test("PlanetTransport upgrades encrypted simple video without disrupting audio", () =>
  testPeerAudio("simple", true));

Deno.test("PlanetTransport ends media on remote REL_REQ (peer hangup)", async () => {
  const routePeer = generateEphemeralKeypair();
  const peerMedia = generateEphemeralKeypair();
  const peerOffer = packNativeSetupOffer({
    mediaPubKey: peerMedia.publicKey,
    mediaKeyId: 0x12345678,
    mediaNonce: new Uint8Array(16).fill(0x44),
    mediaSecret: new Uint8Array(30).fill(0x55),
  });
  const route = makeRoute(routePeer);
  const cid = String(route.stid);
  const replySeed = new Uint8Array(16).fill(0x61);
  const replyLabel = 0x3456;
  const sessId = new Uint8Array(16).fill(0x62);
  let serverSendKeys: TransportKeys | undefined;
  let answerDone = false;
  const sentCcTags: number[] = [];

  const verifyRspPlain = buildControlPlain({
    bodyTag: CC_MSG.VERIFY_RSP,
    bodyBytes: packCcVerifyRsp({
      result: 0,
      oCapas: [1, 2, 7],
      offer: peerOffer,
      oFeatures: [],
    }),
    msgId: 0x2242,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x1001n,
  });
  const connRspPlain = buildControlPlain({
    bodyTag: CC_MSG.CONN_RSP,
    bodyBytes: packCcConnRsp({ result: 0, mChanId: 0x3003n, netType: 1, unavailToSec: 120 }),
    msgId: 0x2244,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x1001n,
  });
  const relReqPlain = buildControlPlain({
    bodyTag: CC_MSG.REL_REQ,
    bodyBytes: packCcRelReq({ relCode: 2, releaser: "initiator", commMediaFlags: 1 }),
    msgId: 0x2245,
    sessId,
    locNonce: 0x123456n,
    cid,
    srcChanId: 0x1001n,
  });

  const transport = new PlanetTransport({
    localMid: "u-local",
    callId: cid,
    timeoutMs: 500,
    keepaliveIntervalMs: 10,
    wireSend(packet, endpoint) {
      if (endpoint.plaintext.length === 519 || endpoint.plaintext.length === 10) return;
      let msg: ReturnType<typeof decodePlanetMsg>;
      try {
        msg = decodePlanetMsg(endpoint.plaintext);
      } catch {
        return;
      }
      if (msg.scBytes) {
        // keepalive tick after the call is up -> simulate the peer hanging up
        if (answerDone && serverSendKeys) {
          return buildServerWire(serverSendKeys, relReqPlain, 0x5103);
        }
        return;
      }
      if (msg.cc?.bodyTag !== undefined) sentCcTags.push(msg.cc.bodyTag);
      if (msg.cc?.bodyTag === CC_MSG.VERIFY_REQ) {
        const clientPub = extractBootstrapClientPub(packet);
        serverSendKeys = deriveCallKeys({
          mpkey: clientPub,
          local: routePeer,
          bootstrapSeed: replySeed,
          sendLabel: replyLabel,
          recvLabel: replyLabel,
        }).send;
        return buildServerWire(serverSendKeys, verifyRspPlain, 0x5101, {
          bootstrap: { label: replyLabel, seed: replySeed, pub: routePeer.publicKey },
        });
      }
      if (msg.cc?.bodyTag === CC_MSG.CONN_REQ) {
        assert(serverSendKeys);
        return buildServerWire(serverSendKeys, connRspPlain, 0x5102);
      }
    },
  });

  await transport.connect({ route });
  const result = await transport.answer();
  assert(result.mediaReady);
  answerDone = true;

  // Peer hangs up on the next keepalive: receive() must terminate instead of
  // hanging in-call forever.
  const received: Uint8Array[] = [];
  await withTimeout(
    (async () => {
      for await (const payload of transport.receive()) received.push(payload);
    })(),
    2000,
    "receive ends on REL",
  );
  assertEquals(transport.remoteEnded, true);
  assert((transport.remoteEndReason ?? "").includes("relCode=2"));
  // Local side must not answer a release with its own REL_REQ.
  assertEquals(sentCcTags.includes(CC_MSG.REL_REQ), false);
  await transport.close();
});
