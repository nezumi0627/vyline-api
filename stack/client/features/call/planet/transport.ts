/**
 * PLANET transport — full state-machine implementation.
 *
 * Flow:
 *   1. acquireRoute (caller already did)
 *   2. connect(route): generate ephemeral keypair, derive session keys
 *      via 2-stage HKDF, open UDP socket to cscf
 *   3. invite(to): send SETUP_REQ (planet_msg with cc_msg.setup_req,
 *      rmt_nonce=0 since we don't yet know cscf's loc_nonce)
 *   4. First reply: decrypt, parse planet_msg_hdr,
 *      extract cscf's loc_nonce → use as session.rmtNonce going forward
 *      (libandromeda 0xcaa524: `str x8, [x19, #0xa0]`)
 *   5. Subsequent sends: include the captured rmt_nonce
 *   6. close(): send REL_REQ
 */

import { Buffer } from "node:buffer";
import type { Socket as DgramSocket } from "node:dgram";
import type * as LINETypes from "@vyline/line-types";
import type { CallAudioProfile, CallKind, CallTransport } from "../session.ts";
import { AudioActivityDetector } from "../audio.js";
import { makeChunkHdr, parseFrameHeader } from "./framing.js";
import { depacketizeEas2, packetizeEas2, packetizeEas2Frames } from "./eas2.js";
import { buildGroupVsd, readPlanetRtpExtension, unpackXrtp } from "./xrtp.js";
import { buildPdtp, parsePdtp, PdtpReceiver, type PdtpPacket } from "./pdtp.js";
import { ConferenceState, type ConferenceMember } from "./conference.js";
import type { CallAudioPacket } from "../groupAudio.js";
import {
  Evs3Assembler,
  packetizeEvs3,
  parseEvs3,
  validateVp8,
  type EncodedVideoFrame,
} from "./evs3.js";
import { packetizeSvcVp8, unwrapSvcVp8, parseSvcVfd } from "./svc.js";
import {
  aesCtrDecrypt,
  aesCtrEncrypt,
  buildDirectionLabel,
  buildPlanetCtrIv,
  decodeMpKey,
  derivePlanetMediaKeyingVariants,
  derivePlanetMediaStreamKeying,
  ecdh,
  type EphemeralKeypair,
  generateEphemeralKeypair,
  hmacTag,
  newSessionId,
  planetHkdfStage1,
  planetHkdfStage2,
  type PlanetMediaKeyVariantName,
  sha256,
  tagEquals,
  type TransportKeys,
} from "./crypto.js";
import {
  CC_MSG,
  type CcConnReq,
  type CcParticipateReq,
  type CcSetupReq,
  type CcVerifyReq,
  decodeCcConnReq,
  decodeCcConnRsp,
  decodeCcInfoReq,
  decodeCcParticipateRsp,
  decodeCcPushReq,
  decodeCcRelReq,
  decodeCcSetupRsp,
  decodeCcVerifyRsp,
  type DecodedField,
  decodeFields,
  decodeMcDataReq,
  decodeMcDataRsp,
  decodeMcNotifyStrmReq,
  decodeMcStrmReq,
  decodeMcStreamControl,
  decodeNativeSetupOffer,
  decodePlanetAddr,
  decodePlanetMsg,
  encodeVarint,
  extractRmtNonceFromReply,
  MC_MSG,
  type NativeSetupOffer,
  packBepiChannelOpen,
  packCcConnReq,
  packCcConnRsp,
  packCcInfoReq,
  packCcInfoRsp,
  packCcParticipateReq,
  packCcRelReq,
  packCcSetupReq,
  packCcVerifyReq,
  packKeepaliveReq,
  packMcChangeRsp,
  packMcCheckRpt,
  packMcDataReq,
  packMcDataRsp,
  packMcDataSessionPayload,
  packMcStreamControl,
  packMcStrmReq,
  packMcJoinRsp,
  packNativeGroupParticipateOffer,
  packNativeSetupOffer,
  packPlanetCcMsg,
  packPlanetFeatureRegister,
  packPlanetMcMsg,
  packPlanetMsg,
  packPlanetScMsgKaReq,
  packPlanetUeInfo,
  packPlanetUserAgent,
  packStrmSpec,
  type PlanetAddr,
  type PlanetMsgHdr,
  type PlanetSetupOfferMaterial,
  type PlanetUserAgent,
  WireType,
  wrapCcMsg,
  wrapMcMsg,
} from "./schema.js";
import {
  buildRtp,
  deriveSrtpContext,
  parseRtp,
  type SrtpCryptoContext,
  srtpDecrypt,
  srtpEncrypt,
} from "../srtp.js";

export interface PlanetTransportOpts {
  localMid: string;
  /** Existing server call id for an incoming Talk notification. */
  callId?: string;
  deviceInfo?: string;
  userAgent?: PlanetUserAgent;
  deviceId?: string;
  transportKeypair?: EphemeralKeypair;
  setupOffer?: Uint8Array;
  credential?: Uint8Array;
  serviceKey?: string;
  capabilities?: number[];
  features?: Uint8Array[];
  timeoutMs?: number;
  keepaliveIntervalMs?: number;
  mediaKeyMode?: PlanetMediaKeyMode;
  rtpTimestampStep?: number;
  preferIpv6?: boolean;
  groupDataSessionAfterProvisional?: boolean;
  wireSend?: (
    packet: Uint8Array,
    endpoint: {
      host: string;
      port: number;
      bootstrap: boolean;
      seq: number;
      plainLen: number;
      bodyLen: number;
      plaintext: Uint8Array;
    },
  ) => Promise<Uint8Array | void> | Uint8Array | void;
  debug?: (event: Record<string, unknown>) => void;
}

export type PlanetMediaKeyMode =
  | "current"
  | "reverse-stage"
  | "sender-material"
  | "sender-material-reverse-stage"
  | "audio-current"
  | "audio-reverse-stage"
  | "audio-sender-material"
  | "audio-sender-material-reverse-stage"
  | "secret-receiver"
  | "secret-sender"
  | "audio-secret-receiver"
  | "audio-secret-sender"
  | "auto";

type MediaKdfMode = Extract<
  PlanetMediaKeyMode,
  "current" | "reverse-stage" | "sender-material" | "sender-material-reverse-stage"
>;

export interface PlanetInviteResult {
  plaintext: Uint8Array;
  message: ReturnType<typeof decodePlanetMsg>;
  setupRsp?: ReturnType<typeof decodeCcSetupRsp>;
}

export interface PlanetIncomingMessage {
  plaintext: Uint8Array;
  message?: ReturnType<typeof decodePlanetMsg>;
}

export interface PlanetAnswerResult {
  plaintext: Uint8Array;
  message: ReturnType<typeof decodePlanetMsg>;
  connReq: CcConnReq;
  peerAnswerOffer?: NativeSetupOffer;
  peerOffer?: NativeSetupOffer;
  connRspSent: boolean;
  mediaReady: boolean;
}

export interface PlanetIncomingAnswerResult {
  verifyRsp: ReturnType<typeof decodeCcVerifyRsp>;
  connRsp: ReturnType<typeof decodeCcConnRsp>;
  peerOffer?: NativeSetupOffer;
  mediaReady: boolean;
}

export interface PlanetGroupJoinResult {
  plaintext: Uint8Array;
  message: ReturnType<typeof decodePlanetMsg>;
  participateRsp?: ReturnType<typeof decodeCcParticipateRsp>;
  peerAnswerOffer?: NativeSetupOffer;
  mediaReady: boolean;
}

export interface PlanetLocalMediaOffer {
  keypair: EphemeralKeypair;
  material: PlanetSetupOfferMaterial;
  offer: Uint8Array;
}

interface CallRouteParsed {
  cscfHost: string;
  cscfPort: number;
  cscfHost6?: string;
  peerPub: Uint8Array;
  toMid: string;
  fromToken: string;
  iZone?: string;
  rZone?: string;
  stid?: string;
  stnpk?: string;
  groupToken?: string;
  orionIp?: string;
  mixIp?: string;
  mixPort?: number;
  mediaHost?: string;
  mediaPort?: number;
}

interface MediaKeySelection {
  mode: MediaKdfMode;
  send: PlanetMediaKeyVariantName;
  recv: PlanetMediaKeyVariantName;
}

interface MediaKeyCandidate {
  mode: Exclude<PlanetMediaKeyMode, "auto">;
  send: string;
  recv: string;
  sendContext: SrtpCryptoContext;
  recvContext: SrtpCryptoContext;
  videoSendContext: SrtpCryptoContext;
  videoRecvContext: SrtpCryptoContext;
}

interface RtpDatagram {
  packet: Uint8Array;
  source: { host: string; port: number } | undefined;
}

const MEDIA_KEY_SELECTIONS: Record<MediaKdfMode, MediaKeySelection> = {
  current: {
    mode: "current",
    send: "local-peer/peer",
    recv: "peer-local/local",
  },
  "reverse-stage": {
    mode: "reverse-stage",
    send: "peer-local/local",
    recv: "local-peer/peer",
  },
  "sender-material": {
    mode: "sender-material",
    send: "local-peer/local",
    recv: "peer-local/peer",
  },
  "sender-material-reverse-stage": {
    mode: "sender-material-reverse-stage",
    send: "peer-local/peer",
    recv: "local-peer/local",
  },
};

function audioMediaKeyMode(mode: MediaKdfMode): Exclude<PlanetMediaKeyMode, "auto"> {
  return `audio-${mode}` as Exclude<PlanetMediaKeyMode, "auto">;
}

function parseRoute(r: LINETypes.CallRoute): CallRouteParsed {
  const commParam = JSON.parse(r.commParam || "{}");
  const mpkeyB64 = commParam.mpkey;
  if (!mpkeyB64) throw new Error("CallRoute.commParam.mpkey missing");
  return {
    cscfHost: r.voipAddress.split(",")[0],
    cscfPort: r.voipUdpPort,
    cscfHost6: r.voipAddress6?.split(",")[0],
    peerPub: decodeMpKey(mpkeyB64),
    toMid: r.toMid,
    fromToken: r.fromToken,
    iZone: r.fromZone,
    rZone: r.toZone,
    stid: r.stid,
    stnpk: r.stnpk,
  };
}

function parseGroupRoute(r: LINETypes.GroupCallRoute): CallRouteParsed {
  const commParam = JSON.parse(r.commParam || "{}");
  const mpkeyB64 = commParam.mpkey;
  if (!mpkeyB64) throw new Error("GroupCallRoute.commParam.mpkey missing");
  return {
    cscfHost: r.voipAddress.split(",")[0],
    cscfPort: r.voipUdpPort,
    cscfHost6: r.voipAddress6?.split(",")[0],
    peerPub: decodeMpKey(mpkeyB64),
    toMid: r.hostMid ?? "",
    fromToken: r.token,
    iZone: r.fromZone,
    rZone: r.polarisZone,
    stnpk: r.stnpk,
    groupToken: r.token,
    orionIp: r.orionAddress,
    mixIp: r.polarisAddress,
    mixPort: r.polarisUdpPort,
    mediaHost: r.voipAddress.split(",")[0],
    mediaPort: r.voipUdpPort,
  };
}

function isGroupRoute(
  r: LINETypes.CallRoute | LINETypes.GroupCallRoute,
): r is LINETypes.GroupCallRoute {
  return "token" in r && !("toMid" in r);
}

const HEADER_LEN = 6;
const BOOTSTRAP_PREFIX_LEN = 51;
const BOOTSTRAP_SEC_HEADER_LEN = 5;
const BOOTSTRAP_CIPHER_OFFSET = HEADER_LEN + BOOTSTRAP_PREFIX_LEN + BOOTSTRAP_SEC_HEADER_LEN;
const CASSINI_MSG_ID_CC_BASE = 0x2140;
const CASSINI_MSG_ID_SETUP_REQ = 0x2141;
const CASSINI_MSG_ID_VERIFY_REQ = 0x2142;
const CASSINI_MSG_ID_CONN_REQ = 0x2144;
const CASSINI_MSG_ID_REL_REQ = 0x2145;
const CASSINI_MSG_ID_GROUP_PARTICIPATE_REQ = 0x214e;
const CASSINI_MSG_ID_MC_JOIN_RSP = 0x3285;
const CASSINI_MSG_ID_MC_CHANGE_RSP = 0x3286;
const CASSINI_MSG_ID_MC_CHECK_RPT = 0x3287;
const CASSINI_MSG_ID_MC_DATA_REQ = 0x3189;
const CASSINI_MSG_ID_MC_DATA_RSP = 0x3289;
const CASSINI_MSG_ID_KEEPALIVE_REQ = 0x1101;
const CASSINI_MSG_ID_BEPI_OPEN = 0x1102;
const REGULAR_TAIL_CONTROL_BASE = 0x18;
const REGULAR_TAIL_RAW_BASE = 0x48;
const PINHOLE_PROBE_COUNT = 16;
const PINHOLE_KIND = 16;
const PINHOLE_MTU = 300;
const PINHOLE_REPORT_MTU = 500;
const PINHOLE_PAYLOAD_BYTES = 500;
const PINHOLE_ID_HIGH_BIT = 1n << 47n;
const PINHOLE_ID_MASK = (1n << 48n) - 1n;
let lastPinholeProbeId = 0n;

function readObservedSequence(wire: Uint8Array): number {
  if (wire.length < HEADER_LEN) throw new Error("PLANET wire too short");
  return ((wire[2] << 8) | wire[3]) & 0xffff;
}

function readCipherSequence(wire: Uint8Array, cipherOffset: number): number {
  // Native PLANET stores the CTR sequence in clear header bytes 2..3 for
  // bootstrap and regular packets alike. The remaining two fixed-header bytes
  // encode the payload length/class.
  if (cipherOffset !== BOOTSTRAP_CIPHER_OFFSET && cipherOffset !== HEADER_LEN) {
    throw new Error("readCipherSequence: unknown cipher offset");
  }
  return readObservedSequence(wire);
}

function looksBootstrapFrame(wire: Uint8Array): boolean {
  return wire.length >= BOOTSTRAP_CIPHER_OFFSET + 16 && wire[4] === 0x06 && wire[5] === 0x02;
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

function packVarintField(tag: number, value: bigint | number): Uint8Array {
  return concatBytes([encodeVarint((tag << 3) | WireType.Varint), encodeVarint(value)]);
}

function packBytesField(tag: number, value: Uint8Array): Uint8Array {
  return concatBytes([
    encodeVarint((tag << 3) | WireType.LengthDelim),
    encodeVarint(value.length),
    value,
  ]);
}

function randomBytes(byteLength: number): Uint8Array {
  const out = new Uint8Array(byteLength);
  crypto.getRandomValues(out);
  return out;
}

function bytesToHex(bytes: Uint8Array, maxBytes: number): string {
  const view = bytes.subarray(0, Math.min(bytes.length, maxBytes));
  return Array.from(view, (b) => b.toString(16).padStart(2, "0")).join("");
}

function nextPinholeProbeId(): bigint {
  const nowNs = BigInt(Math.floor((performance.timeOrigin + performance.now()) * 1_000_000));
  let value = (nowNs & PINHOLE_ID_MASK) | PINHOLE_ID_HIGH_BIT;
  if (value <= lastPinholeProbeId) {
    value = ((lastPinholeProbeId + 1n) & PINHOLE_ID_MASK) | PINHOLE_ID_HIGH_BIT;
  }
  lastPinholeProbeId = value;
  return value;
}

function packPinholeProbe(): Uint8Array {
  const inner = concatBytes([
    packVarintField(1, PINHOLE_KIND),
    packVarintField(2, nextPinholeProbeId()),
    packVarintField(3, PINHOLE_MTU),
    packBytesField(4, randomBytes(PINHOLE_PAYLOAD_BYTES)),
  ]);
  return packBytesField(3, inner);
}

function packPinholeProbeReport(): Uint8Array {
  return packBytesField(
    1,
    concatBytes([
      packVarintField(1, PINHOLE_REPORT_MTU),
      packVarintField(2, PINHOLE_KIND),
      packVarintField(3, PINHOLE_MTU),
    ]),
  );
}

function ccMsgId(bodyTag: number): number {
  if (bodyTag === CC_MSG.CONN_RSP) return 0x2244;
  if (bodyTag === CC_MSG.REL_REQ) return CASSINI_MSG_ID_REL_REQ;
  if (bodyTag === CC_MSG.REL_RSP) return 0x2245;
  if (bodyTag === CC_MSG.PUSH_RSP) return 0x2250;
  if (bodyTag === CC_MSG.INFO_REQ) return 0x2147;
  if (bodyTag === CC_MSG.INFO_RSP) return 0x2247;
  return CASSINI_MSG_ID_CC_BASE + bodyTag;
}

function buildObservedFrameHeader(
  chunkLogical: number,
  sequence: number,
  tail16: number,
): Uint8Array {
  const chunk = makeChunkHdr(chunkLogical);
  return new Uint8Array([
    chunk & 0xff,
    (chunk >>> 8) & 0xff,
    (sequence >>> 8) & 0xff,
    sequence & 0xff,
    (tail16 >>> 8) & 0xff,
    tail16 & 0xff,
  ]);
}

function buildBootstrapSecHeader(plaintextLen: number): Uint8Array {
  // Native first SETUP packet inserts this 5-byte cleartext record
  // between the bootstrap prefix and AES output. Captures with 873/874 byte
  // plaintexts produced 00 00 00 2b 69/6a respectively.
  return new Uint8Array([0, 0, 0, 0x28 | ((plaintextLen >>> 8) & 0x07), plaintextLen & 0xff]);
}

function regularTail16(plaintextLen: number, raw: boolean): number {
  const base = raw ? REGULAR_TAIL_RAW_BASE : REGULAR_TAIL_CONTROL_BASE;
  return (((base | ((plaintextLen >>> 8) & 0x07)) << 8) | (plaintextLen & 0xff)) & 0xffff;
}

function randomBase64(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return btoa(String.fromCharCode(...bytes));
}

function defaultAndroidUserAgent(deviceInfo?: string): PlanetUserAgent {
  return {
    osName: "Android",
    osVersion: "36",
    deviceName: "Pixel 6a",
    appVersion: "12.1.13-63078245f",
    engineVersion: "8.2.0-694e2367",
    appReleaseInfo: deviceInfo ?? "ANDROID\t26.6.2\tAndroid OS\t16",
    manufacturer: "google",
  };
}

function defaultOneToOneStrmSpec(): Uint8Array {
  const state = { paused: false, code: 0 };
  return packStrmSpec({
    strms: [
      {
        ssrc: 102,
        bitrate: { target: 32 },
        state,
        ptime: 40,
        retx: { periOn: true, periIntvMs: 40, periLossThre: [0, 0, 20] },
        fecLossThre: [],
      },
      {
        ssrc: 112,
        bitrate: { min: 100, max: 1200, target: 800 },
        state,
        retx: { periOn: false },
        fecLossThre: [0, 1, 10],
      },
      {
        ssrc: 122,
        bitrate: { max: 2000 },
        state,
        retx: { periOn: false },
        fecLossThre: [],
      },
    ],
    fbIntv: 200,
    tp: 1,
    fbOn: true,
    txStrms: [
      {
        ssrc: 202,
        state,
        retx: { reqdOn: true, reqdRttThre: 300 },
      },
      {
        ssrc: 212,
        state,
        retx: { reqdOn: false },
      },
    ],
    link: {
      bwInitKbps: 886,
      bwMaxKbps: 3000,
      probeRate: 0.2,
      probeBrMaxKbps: 200,
    },
  });
}

function defaultOneToOneDataSessionPayload(): Uint8Array {
  return packMcDataSessionPayload(defaultOneToOneStrmSpec());
}

function defaultSetupFeatures(): Uint8Array[] {
  return [
    packPlanetFeatureRegister(16, true, 0),
    packPlanetFeatureRegister(17, false, 0),
    packPlanetFeatureRegister(0, false, 0),
  ];
}

function defaultGroupParticipateFeatures(): Uint8Array[] {
  return [packPlanetFeatureRegister(16, true, 0), packPlanetFeatureRegister(17, false, 0)];
}

function randomU32(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0];
}

function randomIntInclusive(min: number, max: number): number {
  return min + (randomU32() % (max - min + 1));
}

function randomBitLength(minBits: number, maxBits: number): number {
  const bits = randomIntInclusive(minBits, maxBits);
  const base = 1 << (bits - 1);
  return (base | (randomU32() & (base - 1))) >>> 0;
}

function randomVarint2(): number {
  return (0x2000 | (randomU32() & 0x1fff)) >>> 0;
}

function randomNativeTranSeq(): number {
  return randomBitLength(26, 30);
}

function randomNativeLargeId(): number {
  return randomBitLength(29, 30);
}

function randomNativeGroupCcChanId(): number {
  return randomBitLength(28, 28);
}

function randomNativeGroupMediaChanId(): number {
  return randomBitLength(31, 31);
}

function randomInitialFrameSeq(): number {
  return randomIntInclusive(1, 1023);
}

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function cloneMediaOfferMaterial(material: PlanetSetupOfferMaterial): PlanetSetupOfferMaterial {
  return {
    mediaPubKey: copyBytes(material.mediaPubKey),
    mediaKeyId: material.mediaKeyId,
    mediaNonce: copyBytes(material.mediaNonce),
    mediaSecret: copyBytes(material.mediaSecret),
  };
}

function tryDecodeNativeSetupOffer(bytes: Uint8Array | undefined): NativeSetupOffer | undefined {
  if (!bytes) return undefined;
  try {
    return decodeNativeSetupOffer(bytes);
  } catch {
    return undefined;
  }
}

function fieldShape(fields: DecodedField[]): Array<{
  tag: number;
  wt: number;
  len?: number;
  scalar?: number | string;
}> {
  return fields.map((f) => ({
    tag: f.tag,
    wt: f.wireType,
    len: f.value instanceof Uint8Array ? f.value.length : undefined,
    scalar:
      typeof f.value === "bigint"
        ? f.value <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(f.value)
          : f.value.toString()
        : undefined,
  }));
}

function fieldNumber(fields: DecodedField[], tag: number): number | undefined {
  const v = fields.find((f) => f.tag === tag)?.value;
  return typeof v === "bigint" ? Number(v) : undefined;
}

function fieldText(fields: DecodedField[], tag: number): string | undefined {
  const v = fields.find((f) => f.tag === tag)?.value;
  if (!(v instanceof Uint8Array)) return undefined;
  const s = new TextDecoder().decode(v);
  return /^[\x20-\x7e]{0,80}$/.test(s) ? s : undefined;
}

function defaultLocalMediaOffer(initialVideo = false): PlanetLocalMediaOffer {
  const media = generateEphemeralKeypair();
  const material: PlanetSetupOfferMaterial = {
    mediaPubKey: media.publicKey,
    mediaKeyId: randomNativeLargeId(),
    mediaNonce: crypto.getRandomValues(new Uint8Array(16)),
    mediaSecret: crypto.getRandomValues(new Uint8Array(30)),
  };
  return {
    keypair: {
      publicKey: copyBytes(media.publicKey),
      privateKey: copyBytes(media.privateKey),
    },
    material: cloneMediaOfferMaterial(material),
    offer: packNativeSetupOffer(material, undefined, { enabled: initialVideo }),
  };
}

function defaultSetupCredential(
  route: CallRouteParsed,
  initiator: string,
  responder: string,
  cid: string,
): Uint8Array {
  return sha256(
    concatBytes([
      new TextEncoder().encode(initiator),
      new TextEncoder().encode("::"),
      new TextEncoder().encode(responder),
      new TextEncoder().encode("::"),
      new TextEncoder().encode(route.fromToken),
      new TextEncoder().encode("::"),
      new TextEncoder().encode(cid),
    ]),
  );
}

function defaultGroupParticipateCredential(
  route: CallRouteParsed,
  participant: string,
  roomId: string,
  cid: string,
): Uint8Array {
  if (!route.groupToken) throw new Error("GroupCallRoute.token missing");
  return sha256(
    concatBytes([
      new TextEncoder().encode(participant),
      new TextEncoder().encode("::"),
      new TextEncoder().encode(roomId),
      new TextEncoder().encode("::"),
      new TextEncoder().encode(route.groupToken),
      new TextEncoder().encode("::"),
      new TextEncoder().encode(cid),
    ]),
  );
}

function isRtpLike(wire: Uint8Array): boolean {
  if (wire.length < 12 || (wire[0] & 0xc0) !== 0x80) return false;
  // RFC 5761: RTCP payload types are 200-211 (SR, RR, SDES, BYE, APP, RTPFB, PSFB, etc.)
  const pt = wire[1];
  if (pt >= 200 && pt <= 211) return false;
  return true;
}

function isRtcpLike(wire: Uint8Array): boolean {
  return wire.length >= 8 && (wire[0] & 0xc0) === 0x80 && wire[1] >= 200 && wire[1] <= 211;
}

function firstPort(ports: string | undefined): number | undefined {
  if (!ports) return undefined;
  const hit = ports.match(/\d+/);
  if (!hit) return undefined;
  const port = Number(hit[0]);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : undefined;
}

function addrEndpoint(addr: PlanetAddr | undefined): { host: string; port: number } | undefined {
  if (!addr?.ip) return undefined;
  if (addr.trpt !== undefined && addr.trpt !== 0 && addr.trpt !== 1) return undefined;
  const port = typeof addr.port === "number" ? addr.port : firstPort(addr.ports);
  if (typeof port !== "number" || !Number.isInteger(port) || port <= 0 || port > 65535)
    return undefined;
  return { host: addr.ip, port };
}

function bridgeInfoAddr(bytes: Uint8Array | undefined): PlanetAddr | undefined {
  if (!bytes) return undefined;
  try {
    const addr = decodeFields(bytes).find((f) => f.tag === 1 && f.value instanceof Uint8Array)
      ?.value as Uint8Array | undefined;
    return addr ? decodePlanetAddr(addr) : undefined;
  } catch {
    return undefined;
  }
}

export class PlanetTransport implements CallTransport {
  #opts: PlanetTransportOpts;
  #deviceId: string;
  #sock?: DgramSocket;
  #route?: CallRouteParsed;
  #local?: EphemeralKeypair;
  #sendKeys?: TransportKeys;
  #recvKeys?: TransportKeys;
  #sessId?: Uint8Array;
  #bootstrapSeed?: Uint8Array;
  #sendLabel = 0;
  #callUuid?: string;
  #negotiatedCallId?: string;
  #callUuid16?: Uint8Array;
  #localMediaOffer?: PlanetLocalMediaOffer;
  #localMediaChanId = 1n;
  #srtpSend?: SrtpCryptoContext;
  #srtpRecv?: SrtpCryptoContext;
  #groupDataSrtpSend?: SrtpCryptoContext;
  #dataSrtpRecv?: SrtpCryptoContext;
  #dataPayloadType?: number;
  #mediaKeyMode?: PlanetMediaKeyMode;
  #mediaKeyCandidates: MediaKeyCandidate[] = [];
  #rtp?: {
    host: string;
    port: number;
    payloadType: number;
    ssrc: number;
    seq: number;
    timestamp: number;
  };
  #groupDataRtp?: {
    ssrc: number;
    number: bigint;
  };
  #pdtp = new PdtpReceiver();
  #conference = new ConferenceState();
  onConference?: (members: ConferenceMember[]) => void;
  #rtpQueue: RtpDatagram[] = [];
  #rtpWaiters: Array<(packet: RtpDatagram | null) => void> = [];
  #initialVideo = false;
  #videoEnabled = false;
  #videoStarted = false;
  #groupVideoRequested = false;
  #groupVideoNeedsKey = true;
  #groupVideoCodec: 3 | 4 | undefined = 3;
  #videoRtp?: {
    payloadType: number;
    ssrc: number;
    recvSsrc: number;
    seq: number;
    pictureId: number;
    resolution?: 0 | 1 | 2 | 3;
  };
  #videoSend?: SrtpCryptoContext;
  #videoRecv?: SrtpCryptoContext;
  #videoQueue: RtpDatagram[] = [];
  #videoWaiters: Array<(packet: RtpDatagram | null) => void> = [];
  #videoAssembler = new Evs3Assembler((reason) => this.#debug({ type: "video_ignored", reason }));
  #groupVideoSources = new Map<number, string>();
  #groupVideoAssemblers = new Map<
    number,
    { assembler: Evs3Assembler; spatialId?: number; receivingSpatialId?: number }
  >();
  #pausedGroupVideo = new Set<number>();
  #notifiedVideoChannels = new Map<number, number>();
  #groupVideoSubscriptions = new Map<number, { mid: string; channel: number }>();
  #subscriptionDirty = false;
  #subscriptionGeneration = 0;
  #subscriptionSequence = 0;
  #subscriptionSync?: Promise<void>;
  #subscriptionControl?: {
    tranId: Uint8Array;
    resolve: () => void;
    reject: (error: Error) => void;
  };
  #videoControl?: {
    tranId: Uint8Array;
    resolve: (data: Uint8Array | undefined) => void;
    reject: (error: Error) => void;
  };
  onVideoState?: (enabled: boolean) => void;
  #keepaliveTimer?: ReturnType<typeof setTimeout>;
  #srcChanId = 1n;
  #setupSent = false;
  #groupJoined = false;
  #groupDataSessionSent = false;
  #groupAudioSsrc?: number;
  #pendingGroupAudio: Array<{ opus: Uint8Array; audio?: { level: number; signal: 0 | 1 | 2 } }> =
    [];
  #groupActivity = new AudioActivityDetector();
  #groupRxAudioSsrc?: number;
  #groupDataSsrc?: number;
  #groupRxDataSsrc?: number;
  #remoteCcChanId = 0n;
  #remoteMediaChanId = 0n;
  #targetMid?: string;
  #incomingCall = false;
  /** True once the peer released the call (REL_REQ). receive() then terminates. */
  #remoteEnded = false;
  #remoteEndReason?: string;
  #closed = true;
  #autoConnRspDuplicates = false;
  #connRspDuplicateInFlight = false;
  #audioSent = false;

  // Per-msg sequence + protocol state
  #nextSeq = 0x01d0;
  #tranSeq = 1;
  #msgIdCounter = 1;

  // loc_nonce we generate, rmt_nonce we learn from cscf's first reply
  #locNonce = 0n;
  #rmtNonce = 0n;
  #nonceLearned = false;

  #pending: Array<(env: PlanetIncomingMessage | Error) => void> = [];
  #queued: PlanetIncomingMessage[] = [];

  constructor(opts: PlanetTransportOpts) {
    this.#opts = opts;
    this.#deviceId = opts.deviceId ?? randomBase64(32);
  }

  /** True after the peer released the call (REL_REQ). receive() then terminates. */
  get remoteEnded(): boolean {
    return this.#remoteEnded;
  }

  get remoteEndReason(): string | undefined {
    return this.#remoteEndReason;
  }

  get audioProfile(): CallAudioProfile | undefined {
    return {
      frameDurationMs: 20,
      vbr: false,
    };
  }

  get videoAvailable(): boolean {
    return Boolean(this.#videoRtp && this.#videoSend && this.#videoRecv && !this.#closed);
  }

  #debug(event: Record<string, unknown>) {
    try {
      this.#opts.debug?.(event);
    } catch {
      /* debug hooks must never affect transport */
    }
  }

  #planetUserAgent(): PlanetUserAgent {
    return this.#opts.userAgent ?? defaultAndroidUserAgent(this.#opts.deviceInfo);
  }

  get localMediaOffer(): PlanetLocalMediaOffer | undefined {
    const local = this.#localMediaOffer;
    if (!local) return undefined;
    return {
      keypair: {
        publicKey: copyBytes(local.keypair.publicKey),
        privateKey: copyBytes(local.keypair.privateKey),
      },
      material: cloneMediaOfferMaterial(local.material),
      offer: copyBytes(local.offer),
    };
  }

  async connect(opts: {
    route: LINETypes.CallRoute | LINETypes.GroupCallRoute;
    kind?: CallKind;
  }): Promise<void> {
    this.#route = isGroupRoute(opts.route) ? parseGroupRoute(opts.route) : parseRoute(opts.route);
    this.#local = this.#opts.transportKeypair
      ? {
          privateKey: copyBytes(this.#opts.transportKeypair.privateKey),
          publicKey: copyBytes(this.#opts.transportKeypair.publicKey),
        }
      : generateEphemeralKeypair();
    this.#sessId = new Uint8Array(0);
    this.#bootstrapSeed = newSessionId();
    this.#sendLabel = crypto.getRandomValues(new Uint16Array(1))[0];
    this.#callUuid16 = crypto.getRandomValues(new Uint8Array(16));
    this.#callUuid = this.#opts.callId ?? crypto.randomUUID();
    this.#negotiatedCallId = undefined;
    this.#msgIdCounter = randomVarint2();
    this.#tranSeq = randomNativeTranSeq();
    if (this.#route.groupToken) {
      this.#srcChanId = BigInt(randomNativeGroupCcChanId());
      this.#localMediaChanId = BigInt(randomNativeGroupMediaChanId());
    } else {
      this.#srcChanId = BigInt(randomNativeLargeId());
      this.#localMediaChanId = this.#srcChanId;
    }
    this.#nextSeq = randomInitialFrameSeq();
    this.#setupSent = false;
    this.#groupJoined = false;
    this.#groupDataSessionSent = false;
    this.#groupAudioSsrc = undefined;
    this.#pendingGroupAudio = [];
    this.#groupActivity = new AudioActivityDetector();
    this.#groupRxAudioSsrc = undefined;
    this.#groupDataSsrc = undefined;
    this.#groupRxDataSsrc = undefined;
    this.#remoteCcChanId = 0n;
    this.#remoteMediaChanId = 0n;
    this.#targetMid = undefined;
    this.#incomingCall = false;
    this.#remoteEnded = false;
    this.#remoteEndReason = undefined;
    this.#autoConnRspDuplicates = false;
    this.#connRspDuplicateInFlight = false;
    this.#audioSent = false;
    this.#localMediaOffer = undefined;
    this.#srtpSend = undefined;
    this.#srtpRecv = undefined;
    this.#groupDataSrtpSend = undefined;
    this.#dataSrtpRecv = undefined;
    this.#dataPayloadType = undefined;
    this.#mediaKeyMode = undefined;
    this.#mediaKeyCandidates = [];
    this.#rtp = undefined;
    this.#groupDataRtp = undefined;
    this.#pdtp = new PdtpReceiver();
    this.#conference = new ConferenceState();
    this.#rtpQueue = [];
    this.#initialVideo = opts.kind === "VIDEO";
    this.#clearVideo();
    this.#queued = [];
    this.#clearKeepalive();
    this.#closed = false;

    // Native bootstrap uses a local seed/label for the first outbound SETUP.
    // The first inbound packet carries its own seed/label, so receive keys
    // are derived lazily from that packet before HMAC verification.
    this.#sendKeys = this.#deriveSendKeys(this.#bootstrapSeed, this.#sendLabel);
    this.#recvKeys = undefined;

    this.#locNonce = BigInt(randomNativeLargeId());

    if (!this.#opts.wireSend) {
      const dgram = await import("node:dgram");
      const isIPv6 = !!this.#opts.preferIpv6 && !!this.#route.cscfHost6;
      const sock = dgram.createSocket(isIPv6 ? "udp6" : "udp4");
      this.#sock = sock;
      await new Promise<void>((res) =>
        sock.bind({ address: isIPv6 ? "::" : "0.0.0.0", port: 0 }, () => res()),
      );
      sock.on("message", (buf, rinfo) =>
        this.#onWire(new Uint8Array(buf), {
          host: rinfo.address,
          port: rinfo.port,
        }),
      );
    }
  }

  #onWire(wire: Uint8Array, source?: { host: string; port: number }) {
    if (this.#closed) return;
    try {
      this.#debug({
        type: "recv",
        bytes: wire.length,
        rtpLike: isRtpLike(wire),
        sourceFamily: source?.host.includes(":") ? "ipv6" : source ? "ipv4" : "",
        sourcePort: source?.port,
      });
      if (isRtcpLike(wire)) {
        this.#debug({
          type: "rtcp_recv",
          bytes: wire.length,
          payloadType: wire[1],
        });
        return;
      }
      if (this.#srtpRecv && isRtpLike(wire)) {
        const payloadType = wire[1] & 0x7f;
        if (this.#videoRtp?.payloadType === payloadType) {
          if (wire.length > 8192 || wire.length < 22) return;
          const waiter = this.#videoWaiters.shift();
          const datagram = { packet: wire, source };
          if (waiter) waiter(datagram);
          else if (this.#videoQueue.length < 256) this.#videoQueue.push(datagram);
          // Overflow drops video packets only; the assembler resumes at a key frame.
          return;
        }
        this.#debug({
          type: "rtp_recv",
          bytes: wire.length,
          payloadType,
          marker: (wire[1] & 0x80) !== 0,
          seq: wire.length >= 4 ? (wire[2] << 8) | wire[3] : undefined,
          ssrc:
            wire.length >= 12
              ? ((wire[8] << 24) | (wire[9] << 16) | (wire[10] << 8) | wire[11]) >>> 0
              : undefined,
        });
        if (
          this.#rtp &&
          payloadType !== this.#rtp.payloadType &&
          !(this.#groupJoined && payloadType === this.#dataPayloadType)
        ) {
          this.#debug({
            type: "media_ignored",
            reason: "unexpected_payload_type",
            payloadType,
            expectedPayloadType: this.#rtp.payloadType,
          });
          return;
        }
        this.#enqueueRtp(wire, source);
        return;
      }
      if (wire.length < HEADER_LEN + 16) {
        this.#debug({ type: "recv_ignored", reason: "short" });
        return;
      }
      parseFrameHeader(wire);
      const pt = this.#decryptWire(wire);
      if (!pt) {
        this.#debug({ type: "decrypt_fail" });
        return;
      }
      this.#debug({ type: "decrypt_ok", plainBytes: pt.length });
      const incoming: PlanetIncomingMessage = { plaintext: pt };
      let outer: DecodedField[];
      try {
        outer = decodeFields(pt);
      } catch (e) {
        this.#debug({
          type: "raw_plain",
          plainBytes: pt.length,
          head: bytesToHex(pt, 48),
          decodeError: e instanceof Error ? e.message : String(e),
        });
        const w = this.#pending.shift();
        if (w) w(incoming);
        else this.#queued.push(incoming);
        return;
      }
      this.#debug({ type: "plain_shape", outer: fieldShape(outer) });
      if (
        outer.length === 1 &&
        outer[0]?.value instanceof Uint8Array &&
        outer[0].tag !== 1 &&
        outer[0].tag !== 3
      ) {
        this.#debug({
          type: "raw_plain",
          plainBytes: pt.length,
          tag: outer[0].tag,
          bodyLen: outer[0].value.length,
          head: bytesToHex(pt, 48),
        });
      }

      // Parse outer planet_msg to find hdr → extract loc_nonce on first reply
      if (!this.#nonceLearned) {
        try {
          const hdrField = outer.find((f) => f.tag === 1 && f.wireType === WireType.LengthDelim);
          if (hdrField) {
            const hdrBytes = new Uint8Array(hdrField.value as Uint8Array);
            this.#rmtNonce = extractRmtNonceFromReply(hdrBytes);
            this.#nonceLearned = true;
          }
        } catch (_e) {
          /* keep trying on next msg */
        }
      }
      try {
        const msg = decodePlanetMsg(pt);
        incoming.message = msg;
        if (msg.cc?.bodyTag === CC_MSG.REL_REQ || msg.cc?.bodyTag === CC_MSG.PUSH_REQ) {
          const cid = msg.cc.hdr?.cid;
          if (!cid || (cid !== this.#callUuid && cid !== this.#negotiatedCallId)) return;
        }
        const ccBytes = outer.find((f) => f.tag === 3 && f.value instanceof Uint8Array)?.value as
          | Uint8Array
          | undefined;
        if (ccBytes) {
          const ccFields = decodeFields(ccBytes);
          const bodyBytes = ccFields.find((f) => f.tag === 2 && f.value instanceof Uint8Array)
            ?.value as Uint8Array | undefined;
          this.#debug({
            type: "cc_shape",
            cc: fieldShape(ccFields),
            body: bodyBytes ? fieldShape(decodeFields(bodyBytes)) : [],
          });
        }
        if (msg.mc?.bodyBytes) {
          if (
            msg.mc.bodyTag === MC_MSG.STRM_REQ ||
            msg.mc.bodyTag === MC_MSG.STRM_RSP ||
            msg.mc.bodyTag === MC_MSG.NOTIFY_STRM_REQ
          ) {
            const hdr = msg.mc.hdr;
            if (
              !this.#groupJoined ||
              !hdr ||
              !hdr.cid ||
              (hdr.cid !== this.#callUuid && hdr.cid !== this.#negotiatedCallId) ||
              hdr.srcChanId !== this.#remoteMediaChanId ||
              hdr.dstChanId !== this.#localMediaChanId
            )
              return;
            if (msg.mc.bodyTag === MC_MSG.STRM_REQ) {
              const request = decodeMcStrmReq(msg.mc.bodyBytes);
              if (
                !this.#videoRtp ||
                request.requests.some(
                  (r) =>
                    r.ssrc !== this.#videoRtp!.ssrc ||
                    (r.mid !== undefined && r.mid !== this.#opts.localMid),
                )
              )
                return;
              for (const stream of request.requests) {
                const previouslyRequested = this.#groupVideoRequested;
                const previousCodec = this.#groupVideoCodec;
                this.#groupVideoRequested = stream.type === 1;
                if (stream.type === 1) {
                  const codec = stream.layers.find(
                    (layer) => layer.codec === 0 || layer.codec === 1,
                  )?.codec;
                  this.#groupVideoCodec =
                    stream.encoding === 2 || codec === undefined ? undefined : codec === 1 ? 4 : 3;
                }
                if (
                  !previouslyRequested ||
                  !this.#groupVideoRequested ||
                  previousCodec !== this.#groupVideoCodec ||
                  stream.startOperation === 1
                )
                  this.#groupVideoNeedsKey = true;
              }
              // Native 0x57e942 acknowledges receipt independently of codec support.
              // A request selects framing, never enables the user's camera.
              this.#debug({
                type: "group_video_request",
                requests: request.requests.length,
                preferredVp8a: request.requests.some((r) => r.layers.some((l) => l.codec === 1)),
              });
              const response = packPlanetMcMsg(
                { cid: hdr.cid, srcChanId: this.#localMediaChanId, dstChanId: hdr.srcChanId },
                wrapMcMsg(MC_MSG.STRM_RSP, packMcDataRsp({ result: 0, relCode: 0 })),
              );
              void this.#sendEnvelope(
                { kind: "mc", data: response },
                {
                  msgId: 0x328d,
                  tranId: msg.hdr?.tranId,
                  tranSeq: msg.hdr?.tranSeq,
                  rmtNonce: msg.hdr?.locNonce,
                },
              ).catch(() => {});
            } else if (msg.mc.bodyTag === MC_MSG.STRM_RSP) {
              const pending = this.#subscriptionControl;
              if (pending && msg.hdr?.tranId && tagEquals(pending.tranId, msg.hdr.tranId)) {
                const fields = decodeFields(msg.mc.bodyBytes);
                if (fieldNumber(fields, 1) === 0 && (fieldNumber(fields, 2) ?? 0) === 0)
                  pending.resolve();
                else pending.reject(new Error("Group video subscription rejected"));
              }
            } else {
              const updates = decodeMcNotifyStrmReq(msg.mc.bodyBytes);
              for (const update of updates) {
                const mid = this.#groupVideoSources.get(update.ssrc);
                if (!mid || (update.mid !== undefined && update.mid !== mid)) continue;
                const channel =
                  this.#conference.videoSources.find(
                    (source) => source.ssrc === update.ssrc && source.mid === mid,
                  )?.channel ??
                  this.#groupVideoSubscriptions.get(update.ssrc)?.channel ??
                  this.#notifiedVideoChannels.get(update.ssrc);
                if (channel !== undefined && channel !== update.channel) continue;
                if (!this.#conference.hasChannel(update.channel))
                  this.#notifiedVideoChannels.set(update.ssrc, update.channel);
                if (update.state === 2) this.#pausedGroupVideo.delete(update.ssrc);
                else this.#pausedGroupVideo.add(update.ssrc);
              }
              this.#emitConference();
              const rsp = packPlanetMcMsg(
                { cid: hdr.cid, srcChanId: this.#localMediaChanId, dstChanId: hdr.srcChanId },
                wrapMcMsg(MC_MSG.NOTIFY_STRM_RSP, packMcDataRsp({ result: 0, relCode: 0 })),
              );
              void this.#sendEnvelope(
                { kind: "mc", data: rsp },
                {
                  msgId: 0x328f,
                  tranId: msg.hdr?.tranId,
                  tranSeq: msg.hdr?.tranSeq,
                  rmtNonce: msg.hdr?.locNonce,
                },
              ).catch(() => {});
            }
            return;
          }
          const mcFields = decodeFields(msg.mc.bodyBytes);
          this.#debug({
            type: "mc_shape",
            mc: msg.mc.bodyName ?? "",
            mcTag: msg.mc.bodyTag ?? 0,
            body: fieldShape(mcFields),
          });
          if (msg.mc.bodyTag === MC_MSG.DATA_RSP) {
            const pending = this.#videoControl;
            if (pending && msg.hdr?.tranId && tagEquals(pending.tranId, msg.hdr.tranId)) {
              const response = decodeMcDataRsp(msg.mc.bodyBytes);
              if (response.result || response.relCode)
                pending.reject(new Error("Video control rejected"));
              else pending.resolve(response.data);
            }
            this.#debug({
              type: "mc_data_rsp",
              result: fieldNumber(mcFields, 1),
              relCode: fieldNumber(mcFields, 2),
              relPhrase: fieldText(mcFields, 3),
              relPhraseLen: (mcFields.find((f) => f.tag === 3)?.value as Uint8Array | undefined)
                ?.length,
            });
          }
          if (msg.mc.bodyTag === MC_MSG.DATA_REQ) {
            void this.#sendMcDataRsp(
              incoming as PlanetIncomingMessage & {
                message: ReturnType<typeof decodePlanetMsg>;
              },
            ).catch(() => {});
          }
          if (msg.mc.bodyTag === MC_MSG.JOIN_REQ) {
            void this.#sendMcJoinRsp(
              incoming as PlanetIncomingMessage & {
                message: ReturnType<typeof decodePlanetMsg>;
              },
            ).catch(() => {});
          }
          if (msg.mc.bodyTag === MC_MSG.CHANGE_REQ) {
            void this.#sendMcChangeRsp(
              incoming as PlanetIncomingMessage & {
                message: ReturnType<typeof decodePlanetMsg>;
              },
            ).catch(() => {});
          }
        }
        this.#debug({
          type: "planet_msg",
          cc: msg.cc?.bodyName ?? "",
          ccTag: msg.cc?.bodyTag ?? 0,
          mc: msg.mc?.bodyName ?? "",
          mcTag: msg.mc?.bodyTag ?? 0,
        });
        if (msg.hdr?.sessId?.length) this.#sessId = msg.hdr.sessId;
        if (msg.hdr?.locNonce !== undefined) {
          if (this.#nonceLearned && msg.hdr.locNonce !== this.#rmtNonce) {
            this.#debug({
              type: "nonce_changed",
              prev: this.#rmtNonce.toString(),
              next: msg.hdr.locNonce.toString(),
            });
          }
          this.#rmtNonce = msg.hdr.locNonce;
          this.#nonceLearned = true;
        }
        if (msg.cc?.bodyTag === CC_MSG.INFO_REQ && msg.cc.bodyBytes) {
          void this.#sendInfoRsp(
            incoming as PlanetIncomingMessage & {
              message: ReturnType<typeof decodePlanetMsg>;
            },
          ).catch(() => {});
        }
        if (msg.cc?.bodyTag === CC_MSG.PUSH_REQ && msg.cc.bodyBytes) {
          const push = decodeCcPushReq(msg.cc.bodyBytes);
          if (
            this.#groupJoined &&
            push.contentsType === 1 &&
            push.contents?.length &&
            this.#conference.acceptInfo(push.contents, push.compContentsType ?? 0)
          ) {
            this.#emitConference();
          }
          void this.#sendCcResult(
            incoming as PlanetIncomingMessage & {
              message: ReturnType<typeof decodePlanetMsg>;
            },
            CC_MSG.PUSH_RSP,
          ).catch(() => {});
          return;
        }
        if (msg.cc?.bodyTag === CC_MSG.REL_REQ && msg.cc.bodyBytes) {
          let relCode: number | undefined;
          let relPhrase: string | undefined;
          let releaser: string | undefined;
          try {
            const relReq = decodeCcRelReq(msg.cc.bodyBytes);
            relCode = relReq.relCode;
            relPhrase = relReq.relPhrase;
            releaser = relReq.releaser;
            this.#debug({
              type: "rel_req",
              relCode: relReq.relCode,
              relPhrase: relReq.relPhrase,
              relPhraseLen: relReq.relPhrase?.length,
              releaser: relReq.releaser,
              releaserLen: relReq.releaser?.length,
              commMediaFlags: relReq.commMediaFlags,
              userRelCode: relReq.userRelCode,
              userRelCodeLen: relReq.userRelCode?.length,
              roomDestroy: relReq.roomDestroy,
            });
          } catch {
            // Keep processing even if a newer REL shape appears.
          }
          // Native 0x512fab/0x518bb0: a REL routed to this session ends our
          // participation too. Other members leaving are conference updates.
          void this.#handleRemoteRelease(
            incoming as PlanetIncomingMessage & {
              message: ReturnType<typeof decodePlanetMsg>;
            },
            { relCode, relPhrase, releaser },
          );
          return;
        }
        if (msg.cc?.bodyTag === CC_MSG.CONN_REQ && msg.cc.bodyBytes) {
          let connSummary: Record<string, unknown> = {};
          try {
            const probe = decodeCcConnReq(msg.cc.bodyBytes);
            connSummary = {
              mChanId: String(probe.mChanId ?? 0n),
              netType: probe.netType,
              unavailToSec: probe.unavailToSec,
              hasAnswer: Boolean(probe.answer?.length),
              answerLen: probe.answer?.length ?? 0,
              hasOffer: Boolean(probe.offer?.length),
              offerLen: probe.offer?.length ?? 0,
              oCapas: probe.oCapas,
            };
          } catch {
            /* mid-call CONN_REQ の差分特定用。デコード失敗でも応答は試みる */
          }
          this.#debug({
            type: "conn_req",
            bodyBytes: msg.cc.bodyBytes.length,
            srcChanId: String(msg.cc.hdr?.srcChanId ?? 0n),
            dstChanId: String(msg.cc.hdr?.dstChanId ?? 0n),
            autoRsp: this.#autoConnRspDuplicates,
            rspInFlight: this.#connRspDuplicateInFlight,
            ...connSummary,
          });
          void this.#sendDuplicateConnRsp(
            incoming as PlanetIncomingMessage & {
              message: ReturnType<typeof decodePlanetMsg>;
            },
          ).catch(() => {});
        }
      } catch {
        // Keep the raw reply flowing even if a newer message type is unknown.
      }

      const w = this.#pending.shift();
      if (w) w(incoming);
      else this.#queued.push(incoming);
    } catch (_e) {
      this.#debug({ type: "recv_error" });
      // Probably SRTP media or malformed — ignore
    }
  }

  #enqueueRtp(packet: Uint8Array, source?: { host: string; port: number }) {
    if (packet.length > 16 * 1600 + 1024) return;
    const waiter = this.#rtpWaiters.shift();
    const datagram = { packet, source };
    if (waiter) waiter(datagram);
    else {
      if (this.#rtpQueue.length >= 64) this.#rtpQueue.shift();
      this.#rtpQueue.push(datagram);
    }
  }

  #updateRtpEndpointFromSource(source: { host: string; port: number } | undefined) {
    if (!source || !this.#rtp) return;
    if (this.#rtp.host === source.host && this.#rtp.port === source.port) {
      return;
    }
    this.#rtp.host = source.host;
    this.#rtp.port = source.port;
    this.#debug({
      type: "media_endpoint_learned",
      family: source.host.includes(":") ? "ipv6" : "ipv4",
      port: source.port,
    });
  }

  #takeRtp(): Promise<RtpDatagram | null> {
    if (this.#closed) return Promise.resolve(null);
    const queued = this.#rtpQueue.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolve) => this.#rtpWaiters.push(resolve));
  }

  async #decryptMediaRtp(
    wire: Uint8Array,
  ): Promise<{ rtp: Uint8Array; mode: string; switched: boolean }> {
    if (!this.#srtpRecv) {
      throw new Error("PlanetTransport.receive: media not established");
    }
    try {
      return {
        rtp: await srtpDecrypt(this.#srtpRecv, wire),
        mode: String(this.#mediaKeyMode ?? "current"),
        switched: false,
      };
    } catch (e) {
      if (this.#mediaKeyMode !== "auto") throw e;
    }
    for (const candidate of this.#mediaKeyCandidates) {
      if (candidate.recvContext === this.#srtpRecv) continue;
      try {
        const rtp = await srtpDecrypt(candidate.recvContext, wire);
        this.#srtpSend = candidate.sendContext;
        this.#srtpRecv = candidate.recvContext;
        this.#videoSend = candidate.videoSendContext;
        this.#videoRecv = candidate.videoRecvContext;
        this.#debug({
          type: "media_key_selected",
          mode: candidate.mode,
          send: candidate.send,
          recv: candidate.recv,
        });
        return { rtp, mode: candidate.mode, switched: true };
      } catch {
        /* try next candidate */
      }
    }
    throw new Error("SRTP auth tag mismatch");
  }

  #decryptWire(wire: Uint8Array): Uint8Array | null {
    if (wire.length < HEADER_LEN + 16) return null;
    if (looksBootstrapFrame(wire)) {
      const bootstrap = this.#decryptBootstrapWire(wire);
      if (bootstrap) return bootstrap;
      return this.#recvKeys ? this.#decryptWithKeys(wire, this.#recvKeys, HEADER_LEN) : null;
    }
    const regular = this.#recvKeys ? this.#decryptWithKeys(wire, this.#recvKeys, HEADER_LEN) : null;
    if (regular) return regular;
    return this.#decryptBootstrapWire(wire);
  }

  #deriveSendKeys(seed: Uint8Array, label: number): TransportKeys {
    if (!this.#local || !this.#route) throw new Error("connect first");
    const secret = ecdh(this.#local.privateKey, this.#route.peerPub);
    const stage1 = planetHkdfStage1(secret, this.#route.peerPub, this.#local.publicKey);
    return planetHkdfStage2(stage1, seed, buildDirectionLabel(label));
  }

  #deriveRecvKeys(seed: Uint8Array, label: number): TransportKeys {
    if (!this.#local || !this.#route) throw new Error("connect first");
    const secret = ecdh(this.#local.privateKey, this.#route.peerPub);
    const stage1 = planetHkdfStage1(secret, this.#local.publicKey, this.#route.peerPub);
    return planetHkdfStage2(stage1, seed, buildDirectionLabel(label));
  }

  #decryptBootstrapWire(wire: Uint8Array): Uint8Array | null {
    if (wire.length < BOOTSTRAP_CIPHER_OFFSET + 16) return null;
    const label = ((wire[HEADER_LEN] << 8) | wire[HEADER_LEN + 1]) & 0xffff;
    const seed = copyBytes(wire.subarray(HEADER_LEN + 2, HEADER_LEN + 18));
    const keys = this.#deriveRecvKeys(seed, label);
    const plaintext = this.#decryptWithKeys(wire, keys, BOOTSTRAP_CIPHER_OFFSET);
    if (!plaintext) return null;
    this.#recvKeys = keys;
    return plaintext;
  }

  #decryptWithKeys(wire: Uint8Array, keys: TransportKeys, cipherOffset: number): Uint8Array | null {
    if (wire.length < cipherOffset + 16) return null;
    const seq = readCipherSequence(wire, cipherOffset);
    const tag = wire.subarray(wire.length - 16);
    const macInput = wire.subarray(0, wire.length - 16);
    const ct = wire.subarray(cipherOffset, wire.length - 16);
    const expected = hmacTag(keys.macKey, macInput);
    if (!tagEquals(tag, expected)) return null;
    return aesCtrDecrypt(keys.encKey, buildPlanetCtrIv(keys.ctrBase, seq), ct);
  }

  #encrypt(plaintext: Uint8Array, seq: number): Uint8Array {
    if (!this.#sendKeys) throw new Error("not connected");
    return aesCtrEncrypt(
      this.#sendKeys.encKey,
      buildPlanetCtrIv(this.#sendKeys.ctrBase, seq),
      plaintext,
    );
  }

  #bootstrapPrefix(): Uint8Array {
    if (!this.#local || !this.#bootstrapSeed) throw new Error("connect first");
    const label = buildDirectionLabel(this.#sendLabel);
    const out = new Uint8Array(
      label.length + this.#bootstrapSeed.length + this.#local.publicKey.length,
    );
    out.set(label, 0);
    out.set(this.#bootstrapSeed, label.length);
    out.set(this.#local.publicKey, label.length + this.#bootstrapSeed.length);
    return out;
  }

  #planetHdr(
    opts: {
      msgId?: number;
      tranId?: Uint8Array;
      tranSeq?: number;
      rmtNonce?: bigint;
    } = {},
  ): PlanetMsgHdr {
    if (!this.#sessId) throw new Error("connect first");
    let tranId = opts.tranId;
    if (!tranId || tranId.length === 0) {
      tranId = new Uint8Array(16);
      crypto.getRandomValues(tranId);
    }
    return {
      userId: this.#opts.localMid,
      msgId: opts.msgId ?? this.#msgIdCounter++,
      sessId: this.#sessId,
      tranId,
      tranSeq: opts.tranSeq ?? this.#tranSeq++,
      locNonce: this.#locNonce,
      rmtNonce: opts.rmtNonce ?? this.#rmtNonce,
    };
  }

  async #sendEnvelope(
    body: { kind: "sc" | "cc" | "mc"; data: Uint8Array },
    opts: {
      bootstrap?: boolean;
      msgId?: number;
      tranId?: Uint8Array;
      tranSeq?: number;
      rmtNonce?: bigint;
    } = {},
  ): Promise<void> {
    const hdr = this.#planetHdr(opts);
    const planetMsg = packPlanetMsg(hdr, body);
    this.#debug({
      type: "send_planet_msg",
      kind: body.kind,
      msgId: hdr.msgId,
      sessIdBytes: hdr.sessId.length,
      tranIdBytes: hdr.tranId.length,
      tranSeqBits: hdr.tranSeq.toString(2).length,
      locNonceBits: hdr.locNonce.toString(2).length,
      rmtNoncePresent: hdr.rmtNonce !== 0n,
      echoTranId: Boolean(opts.tranId),
    });
    await this.#sendTransportPlaintext(planetMsg, {
      bootstrap: opts.bootstrap,
      raw: false,
    });
  }

  async #sendTransportPlaintext(
    plaintext: Uint8Array,
    opts: { bootstrap?: boolean; raw?: boolean } = {},
  ): Promise<void> {
    if ((!this.#sock && !this.#opts.wireSend) || !this.#route) {
      throw new Error("not connected");
    }
    const seq = this.#nextSeq++;
    const prefix = opts.bootstrap ? this.#bootstrapPrefix() : new Uint8Array(0);
    const sec = opts.bootstrap ? buildBootstrapSecHeader(plaintext.length) : new Uint8Array(0);
    const ct = this.#encrypt(plaintext, seq & 0xffff);
    const tagLen = 16;
    const bodyLen = prefix.length + sec.length + ct.length + tagLen;
    const totalLen = HEADER_LEN + bodyLen;
    const chunkLogical = (((totalLen - 4) << 5) | (opts.bootstrap ? 0x1d : 0x0d)) & 0xffff;
    const hdr = opts.bootstrap
      ? buildObservedFrameHeader(chunkLogical, seq & 0xffff, 0x0602)
      : buildObservedFrameHeader(
          chunkLogical,
          seq & 0xffff,
          regularTail16(plaintext.length, !!opts.raw),
        );
    const macInput = concatBytes([hdr, prefix, sec, ct]);
    const tag = hmacTag(this.#sendKeys!.macKey, macInput);
    const datagram = concatBytes([macInput, tag]);
    const host =
      this.#opts.preferIpv6 && this.#route.cscfHost6 ? this.#route.cscfHost6 : this.#route.cscfHost;
    this.#debug({
      type: "send",
      bootstrap: !!opts.bootstrap,
      raw: !!opts.raw,
      seq,
      bytes: datagram.length,
      plainBytes: plaintext.length,
      bodyBytes: bodyLen,
      family: host.includes(":") ? "ipv6" : "ipv4",
    });
    if (this.#opts.wireSend) {
      const reply = await this.#opts.wireSend(datagram, {
        host,
        port: this.#route.cscfPort,
        bootstrap: !!opts.bootstrap,
        seq,
        plainLen: plaintext.length,
        bodyLen,
        plaintext,
      });
      if ((reply as Uint8Array | undefined)?.length) this.#onWire(reply as Uint8Array);
      return;
    }
    await new Promise<void>((res, rj) =>
      this.#sock!.send(Buffer.from(datagram), this.#route!.cscfPort, host, (e) =>
        e ? rj(e) : res(),
      ),
    );
  }

  async #sendPinholeProbes(): Promise<void> {
    for (let i = 0; i < PINHOLE_PROBE_COUNT; i++) {
      await this.#sendTransportPlaintext(packPinholeProbe(), { raw: true });
    }
    await this.#sendTransportPlaintext(packPinholeProbeReport(), { raw: true });
  }

  #waitForIncoming(timeoutMs: number): Promise<PlanetIncomingMessage> {
    const queued = this.#queued.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((res, rj) => {
      const t = setTimeout(() => rj(new Error("PLANET reply timeout")), timeoutMs);
      this.#pending.push((env) => {
        clearTimeout(t);
        if (env instanceof Error) rj(env);
        else res(env);
      });
    });
  }

  async #waitForCc(
    bodyTag: number,
    timeoutMs: number,
  ): Promise<
    PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    }
  > {
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const remaining = Math.max(1, deadline - Date.now());
      const incoming = await this.#waitForIncoming(remaining);
      if (incoming.message?.cc?.bodyTag === bodyTag && incoming.message.cc.bodyBytes) {
        // Learn at most one server-selected CID from the authenticated join/setup
        // response, never from a later unsolicited PUSH or REL.
        if (
          bodyTag === CC_MSG.SETUP_RSP ||
          bodyTag === CC_MSG.VERIFY_RSP ||
          bodyTag === CC_MSG.PARTICIPATE_RSP
        ) {
          this.#negotiatedCallId ??= incoming.message.cc.hdr?.cid;
        }
        return incoming as PlanetIncomingMessage & {
          message: ReturnType<typeof decodePlanetMsg>;
        };
      }
      if (Date.now() >= deadline) throw new Error("PLANET reply timeout");
    }
  }

  async #sendSetup(opts: { to: string }): Promise<void> {
    if (!this.#route || !this.#local) throw new Error("connect first");
    this.#targetMid = opts.to;
    const cid = this.#callUuid!;
    const localMediaOffer = this.#opts.setupOffer
      ? undefined
      : defaultLocalMediaOffer(this.#initialVideo);
    if (localMediaOffer) this.#localMediaOffer = localMediaOffer;
    const setup: CcSetupReq = {
      initiator: this.#opts.localMid,
      responder: opts.to,
      iZone: this.#route.iZone,
      rZone: this.#route.rZone,
      ua: packPlanetUserAgent(this.#planetUserAgent()),
      devId: this.#deviceId,
      commTypeFlags: this.#initialVideo ? 3 : 1,
      capas: this.#opts.capabilities ?? [1, 2, 3, 6, 7],
      // Native LINE sends a 311-byte structured media/security offer here.
      offer: this.#opts.setupOffer ?? localMediaOffer!.offer,
      // Native credential is SHA-256(initiator::responder::fromToken::cid).
      credential:
        this.#opts.credential ??
        defaultSetupCredential(this.#route, this.#opts.localMid, opts.to, cid),
      fakeCall: false,
      svcKey: this.#opts.serviceKey ?? (this.#initialVideo ? "freecall.video" : "freecall.audio"),
      netType: 1,
      stid: this.#route.stid,
      features: this.#opts.features ?? defaultSetupFeatures(),
      reqRec: false,
      pathCheck: false,
    };
    const setupBytes = packCcSetupReq(setup);
    const ccBody = wrapCcMsg(CC_MSG.SETUP_REQ, setupBytes);
    const ccMsg = packPlanetCcMsg({ cid, srcChanId: this.#srcChanId, dstChanId: 0n }, ccBody);
    await this.#sendEnvelope(
      { kind: "cc", data: ccMsg },
      { bootstrap: true, msgId: CASSINI_MSG_ID_SETUP_REQ },
    );
    this.#setupSent = true;
  }

  async inviteDetailed(opts: { to: string }): Promise<PlanetInviteResult> {
    await this.#sendSetup(opts);
    const reply = await this.#waitForCc(CC_MSG.SETUP_RSP, this.#opts.timeoutMs ?? 10000);
    const setupBytes = reply.message.cc?.bodyBytes;
    if (!setupBytes) throw new Error("PLANET setup_rsp missing body");
    const setupRsp = decodeCcSetupRsp(setupBytes);
    await this.#sendPinholeProbes();
    await this.#sendKeepalive();
    this.#startKeepalive(setupRsp.aliveRptInterval);
    return {
      plaintext: reply.plaintext,
      message: reply.message,
      setupRsp,
    };
  }

  async invite(opts: { to: string }): Promise<Uint8Array> {
    return (await this.inviteDetailed(opts)).plaintext;
  }

  async #sendVerify(): Promise<void> {
    if (!this.#route || !this.#local) throw new Error("connect first");
    const callerMid = this.#route.toMid;
    if (!callerMid) throw new Error("incoming CallRoute.toMid missing");
    this.#incomingCall = true;
    this.#targetMid = callerMid;
    this.#localMediaOffer ??= defaultLocalMediaOffer(this.#initialVideo);
    const cid = this.#callUuid!;
    const verify: CcVerifyReq = {
      initiator: callerMid,
      responder: this.#opts.localMid,
      iZone: this.#route.iZone,
      rZone: this.#route.rZone,
      ua: packPlanetUserAgent(this.#planetUserAgent()),
      devId: this.#deviceId,
      commTypeFlags: this.#initialVideo ? 3 : 1,
      capas: this.#opts.capabilities ?? [1, 2, 3, 6, 7],
      credential:
        this.#opts.credential ??
        defaultSetupCredential(this.#route, callerMid, this.#opts.localMid, cid),
      svcKey: this.#opts.serviceKey ?? (this.#initialVideo ? "freecall.video" : "freecall.audio"),
      crt: false,
      netType: 1,
      stid: this.#route.stid,
      pathCheck: false,
    };
    const ccBody = wrapCcMsg(CC_MSG.VERIFY_REQ, packCcVerifyReq(verify));
    const ccMsg = packPlanetCcMsg({ cid, srcChanId: this.#srcChanId, dstChanId: 0n }, ccBody);
    await this.#sendEnvelope(
      { kind: "cc", data: ccMsg },
      { bootstrap: true, msgId: CASSINI_MSG_ID_VERIFY_REQ },
    );
    this.#setupSent = true;
  }

  async #sendIncomingConnReq(
    verifyReply: PlanetIncomingMessage & { message: ReturnType<typeof decodePlanetMsg> },
  ): Promise<CcConnReq> {
    const local = this.#localMediaOffer;
    if (!local) throw new Error("incoming media offer missing");
    const connReq: CcConnReq = {
      answer: local.offer,
      mChanId: this.#localMediaChanId,
      netType: 1,
      unavailToSec: 120,
      oCapas: this.#opts.capabilities ?? [1, 2, 3, 6, 7],
      features: this.#opts.features ?? defaultSetupFeatures(),
      ua: packPlanetUserAgent(this.#planetUserAgent()),
      devId: this.#deviceId,
      reqRec: false,
    };
    const ccBody = wrapCcMsg(CC_MSG.CONN_REQ, packCcConnReq(connReq));
    const ccMsg = packPlanetCcMsg(
      {
        cid: verifyReply.message.cc?.hdr?.cid ?? this.#callUuid ?? "incoming-call",
        srcChanId: this.#srcChanId,
        dstChanId: verifyReply.message.cc?.hdr?.srcChanId ?? this.#remoteCcChanId,
      },
      ccBody,
    );
    await this.#sendEnvelope({ kind: "cc", data: ccMsg }, { msgId: CASSINI_MSG_ID_CONN_REQ });
    return connReq;
  }

  /**
   * Accept an incoming 1:1 PLANET call.
   * Native responder flow: VERIFY_REQ -> VERIFY_RSP(offer) -> CONN_REQ -> CONN_RSP.
   */
  async answer(): Promise<PlanetIncomingAnswerResult> {
    await this.#sendVerify();
    const verifyReply = await this.#waitForCc(CC_MSG.VERIFY_RSP, this.#opts.timeoutMs ?? 10000);
    const verifyBytes = verifyReply.message.cc?.bodyBytes;
    if (!verifyBytes) throw new Error("PLANET verify_rsp missing body");
    const verifyRsp = decodeCcVerifyRsp(verifyBytes);
    if ((verifyRsp.result ?? 0) !== 0 || (verifyRsp.relCode ?? 0) !== 0) {
      throw new Error(
        `PLANET verify rejected (${verifyRsp.result ?? 0}/${verifyRsp.relCode ?? 0})${
          verifyRsp.relPhrase ? `: ${verifyRsp.relPhrase}` : ""
        }`,
      );
    }
    this.#remoteCcChanId = verifyReply.message.cc?.hdr?.srcChanId ?? this.#remoteCcChanId;
    const peerOffer = tryDecodeNativeSetupOffer(verifyRsp.offer);
    const selectedCrypto =
      peerOffer?.mediaPubKey?.length === 33 &&
      peerOffer.mediaNonce?.length === 16 &&
      peerOffer.mediaKeyId !== undefined
        ? "e2ee"
        : peerOffer?.mediaSecret?.length === 30
          ? "simple"
          : undefined;
    if (!selectedCrypto || !this.#localMediaOffer) {
      throw new Error("PLANET peer offers no supported encrypted media scheme");
    }
    this.#localMediaOffer.offer = packNativeSetupOffer(
      this.#localMediaOffer.material,
      selectedCrypto,
      { enabled: this.#initialVideo },
    );
    // Candidate authentication must stay inside the selected crypto family.
    const negotiatedPeer = { ...peerOffer! };
    if (selectedCrypto === "e2ee") delete negotiatedPeer.mediaSecret;
    else {
      delete negotiatedPeer.mediaPubKey;
      delete negotiatedPeer.mediaKeyId;
      delete negotiatedPeer.mediaNonce;
    }
    const mediaReady = await this.#configureMedia(negotiatedPeer, {
      answer: verifyRsp.offer,
      netType: 1,
      unavailToSec: 120,
      oCapas: verifyRsp.oCapas,
      features: verifyRsp.oFeatures,
    });
    if (!mediaReady) throw new Error("PLANET incoming media negotiation failed");

    await this.#sendPinholeProbes();
    await this.#sendKeepalive();
    this.#startKeepalive(verifyRsp.aliveRptInterval);

    const connReq = await this.#sendIncomingConnReq(verifyReply);
    const connReply = await this.#waitForCc(CC_MSG.CONN_RSP, this.#opts.timeoutMs ?? 10000);
    const connBytes = connReply.message.cc?.bodyBytes;
    if (!connBytes) throw new Error("PLANET conn_rsp missing body");
    const connRsp = decodeCcConnRsp(connBytes);
    if ((connRsp.result ?? 0) !== 0 || (connRsp.relCode ?? 0) !== 0) {
      throw new Error(
        `PLANET connect rejected (${connRsp.result ?? 0}/${connRsp.relCode ?? 0})${
          connRsp.relPhrase ? `: ${connRsp.relPhrase}` : ""
        }`,
      );
    }
    this.#remoteCcChanId = connReply.message.cc?.hdr?.srcChanId ?? this.#remoteCcChanId;
    this.#remoteMediaChanId = connRsp.mChanId ?? this.#remoteMediaChanId;
    await this.#sendExchangeAppStrDataInfoReq(connReply, connReq);
    return { verifyRsp, connRsp, peerOffer, mediaReady };
  }

  async #sendParticipate(opts: { roomId: string }): Promise<void> {
    if (!this.#route || !this.#local) throw new Error("connect first");
    if (!this.#route.groupToken) throw new Error("Group route required");
    const route = this.#route;
    const cid = this.#callUuid!;
    const localMediaOffer = defaultLocalMediaOffer();
    this.#localMediaOffer = localMediaOffer;
    const offer =
      this.#opts.setupOffer ??
      packNativeGroupParticipateOffer(
        { mediaSecret: localMediaOffer.material.mediaSecret },
        this.#initialVideo,
      );
    localMediaOffer.offer = offer;
    const participate: CcParticipateReq = {
      participant: this.#opts.localMid,
      roomId: opts.roomId,
      pZone: route.iZone,
      xZone: route.rZone,
      orionIp: route.orionIp,
      mixIp: route.mixIp,
      ua: packPlanetUserAgent(this.#planetUserAgent()),
      devId: this.#deviceId,
      commTypeFlags: this.#initialVideo ? 3 : 1,
      capas: this.#opts.capabilities ?? [1, 2, 3, 6, 4, 5],
      offer,
      credential:
        this.#opts.credential ??
        defaultGroupParticipateCredential(route, this.#opts.localMid, opts.roomId, cid),
      svcKey: this.#opts.serviceKey ?? (this.#initialVideo ? "groupcall.video" : "groupcall.audio"),
      netType: 1,
      mChanId: this.#localMediaChanId,
      mixPort: route.mixPort,
      features: this.#opts.features ?? defaultGroupParticipateFeatures(),
      roomAttrs: [1],
      recvRtp: 2,
      maxChanCnt: 30,
      unavailToSec: 0,
      pdtpOndemandStreams: [concatBytes([packVarintField(1, 4), packVarintField(2, 2)])],
      ueExtraInfo: packVarintField(1, 1),
      pathCheck: false,
    };
    const participateBytes = packCcParticipateReq(participate);
    this.#debug({
      type: "participate_req",
      bodyBytes: participateBytes.length,
      fields: fieldShape(decodeFields(participateBytes)),
      svcKeyBytes: participate.svcKey?.length,
      offerBytes: participate.offer?.length,
      credentialBytes: participate.credential?.length,
      srcChanIdBits: this.#srcChanId.toString(2).length,
      mChanIdBits: this.#localMediaChanId.toString(2).length,
    });
    const ccBody = wrapCcMsg(CC_MSG.PARTICIPATE_REQ, participateBytes);
    const ccMsg = packPlanetCcMsg({ cid, srcChanId: this.#srcChanId, dstChanId: 0n }, ccBody);
    await this.#sendEnvelope(
      { kind: "cc", data: ccMsg },
      { bootstrap: true, msgId: CASSINI_MSG_ID_GROUP_PARTICIPATE_REQ },
    );
    this.#setupSent = true;
  }

  async #sendGroupDataSessionOpen(
    dstChanId: bigint,
    peerOffer: NativeSetupOffer | undefined,
  ): Promise<void> {
    if (!this.#route) throw new Error("connect first");
    if (this.#groupDataSessionSent) return;
    const cid = this.#callUuid!;
    const sourceIds = (name: string): [number, number] => {
      const media = peerOffer?.media.find((m) => m.name === name);
      const ids = [media?.rtpPort, media?.rtcpId];
      if (ids.some((id) => !Number.isInteger(id) || id! < 0 || id! > 0xffffffff)) {
        throw new Error("Group media source IDs missing");
      }
      return [ids[0]!, ids[1]!];
    };
    // Native 0x515ab0 enumerates negotiated streams; it does not allocate a
    // second set of unrelated SSRCs when constructing the stream specification.
    const [rxAudioSsrc, txAudioSsrc] = sourceIds("A");
    const [rxVideoSsrc, txVideoSsrc] = sourceIds("V");
    const [rxDataSsrc, txDataSsrc] = sourceIds("D");
    this.#groupAudioSsrc = txAudioSsrc;
    this.#groupRxAudioSsrc = rxAudioSsrc;
    this.#groupDataSsrc = txDataSsrc;
    this.#groupRxDataSsrc = rxDataSsrc;
    const state = { paused: false, code: 0 };
    const strmSpec = packStrmSpec({
      strms: [
        {
          ssrc: rxAudioSsrc,
          bitrate: { target: 32 },
          state,
          ptime: 40,
          retx: { periOn: true, periIntvMs: 40, periLossThre: [0, 0, 20] },
          fecLossThre: [],
        },
        {
          ssrc: rxVideoSsrc,
          bitrate: { min: 100, max: 1200, target: 800 },
          state,
          retx: { periOn: false },
          fecLossThre: [0, 1, 10],
        },
        {
          ssrc: rxDataSsrc,
          bitrate: { max: 2000 },
          state,
          retx: { periOn: false },
          fecLossThre: [],
        },
      ],
      fbIntv: 200,
      tp: 1,
      fbOn: true,
      txStrms: [
        {
          ssrc: txAudioSsrc,
          state,
          retx: { reqdOn: true, reqdRttThre: 300 },
        },
        {
          ssrc: txVideoSsrc,
          state,
          retx: { reqdOn: false },
        },
      ],
      link: {
        bwInitKbps: 1200,
        bwMaxKbps: 3000,
        probeRate: 0.2,
        probeBrMaxKbps: 200,
      },
    });
    const data = packMcDataSessionPayload(strmSpec);
    const dataReq = packMcDataReq({
      srcType: 0,
      dstType: 0,
      dispatchId: 2,
      data,
    });
    const mcBody = wrapMcMsg(MC_MSG.DATA_REQ, dataReq);
    const mcMsg = packPlanetMcMsg({ cid, srcChanId: this.#localMediaChanId, dstChanId }, mcBody);
    this.#debug({
      type: "group_data_session_req",
      bodyBytes: dataReq.length,
      dataBytes: data.length,
      strmSpecBytes: strmSpec.length,
      audioSsrc: txAudioSsrc,
      dataSsrc: txDataSsrc,
      dstChanIdBits: dstChanId.toString(2).length,
    });
    await this.#sendEnvelope({ kind: "mc", data: mcMsg }, { msgId: CASSINI_MSG_ID_MC_DATA_REQ });
    this.#groupDataSessionSent = true;
  }

  async joinGroupDetailed(opts: { roomId: string }): Promise<PlanetGroupJoinResult> {
    await this.#sendParticipate(opts);
    const deadline = Date.now() + (this.#opts.timeoutMs ?? 10000);
    let reply:
      | (PlanetIncomingMessage & {
          message: ReturnType<typeof decodePlanetMsg>;
        })
      | undefined;
    let participateRsp: ReturnType<typeof decodeCcParticipateRsp> | undefined;
    while (true) {
      const remaining = Math.max(1, deadline - Date.now());
      reply = await this.#waitForCc(CC_MSG.PARTICIPATE_RSP, remaining);
      const bodyBytes = reply.message.cc?.bodyBytes;
      if (!bodyBytes) throw new Error("PLANET participate_rsp missing body");
      participateRsp = decodeCcParticipateRsp(bodyBytes);
      this.#debug({
        type: "participate_rsp",
        bodyBytes: bodyBytes.length,
        fields: fieldShape(decodeFields(bodyBytes)),
        result: participateRsp.result,
        relCode: participateRsp.relCode,
        answerBytes: participateRsp.answer?.length,
        contentsBytes: participateRsp.contents?.length,
      });
      const remoteChanId = reply.message.cc?.hdr?.srcChanId;
      if (
        this.#opts.groupDataSessionAfterProvisional &&
        !this.#groupDataSessionSent &&
        remoteChanId !== undefined &&
        participateRsp.answer &&
        participateRsp.relCode === undefined &&
        (participateRsp.result === undefined || participateRsp.result === 0)
      ) {
        await this.#sendGroupDataSessionOpen(
          remoteChanId,
          tryDecodeNativeSetupOffer(participateRsp.answer),
        );
      }
      if (
        participateRsp.result !== undefined ||
        participateRsp.relCode !== undefined ||
        participateRsp.answer ||
        participateRsp.contents
      ) {
        break;
      }
      if (Date.now() >= deadline) throw new Error("PLANET reply timeout");
    }
    this.#remoteCcChanId = reply.message.cc?.hdr?.srcChanId ?? 0n;
    if ((participateRsp.result ?? 0) !== 0 || (participateRsp.relCode ?? 0) !== 0) {
      throw new Error(
        `PLANET group participation rejected (${participateRsp.result ?? 0}/${participateRsp.relCode ?? 0})`,
      );
    }
    this.#groupJoined = true;
    if (
      participateRsp.contentsType === 1 &&
      participateRsp.contents?.length &&
      this.#conference.acceptInfo(participateRsp.contents, participateRsp.compContentsType ?? 0)
    ) {
      this.#emitConference();
    }
    this.#remoteMediaChanId = participateRsp.mChanId || this.#remoteCcChanId;
    const mcDstChanId = this.#remoteMediaChanId;
    if (mcDstChanId === 0n) throw new Error("Group media channel missing");
    const peerAnswerOffer = tryDecodeNativeSetupOffer(participateRsp.answer);
    if (!this.#groupDataSessionSent && mcDstChanId !== 0n) {
      await this.#sendGroupDataSessionOpen(mcDstChanId, peerAnswerOffer);
    }
    const bridgeAddr = bridgeInfoAddr(participateRsp.bridgeInfo);
    if (bridgeAddr) {
      this.#debug({
        type: "group_bridge_addr",
        host: bridgeAddr.ip,
        port: bridgeAddr.port ?? bridgeAddr.ports,
        trpt: bridgeAddr.trpt,
      });
    }
    const mediaReady = await this.#configureMedia(peerAnswerOffer, {
      answer: participateRsp.answer,
      mChanId: participateRsp.mChanId,
      netType: 1,
      unavailToSec: 120,
      oCapas: [],
      features: [],
      mAddr: bridgeAddr,
    });
    if (!mediaReady) throw new Error("PLANET group media negotiation failed");
    this.#syncGroupVideoSubscriptions();
    await this.#sendPinholeProbes();
    await this.#sendKeepalive();
    this.#startKeepalive(participateRsp.aliveRptInterval);
    return {
      plaintext: reply.plaintext,
      message: reply.message,
      participateRsp,
      peerAnswerOffer,
      mediaReady,
    };
  }

  async joinGroup(opts: { roomId: string }): Promise<Uint8Array> {
    return (await this.joinGroupDetailed(opts)).plaintext;
  }

  async waitForAnswerDetailed(
    opts: {
      timeoutMs?: number;
      autoConnRsp?: boolean;
    } = {},
  ): Promise<PlanetAnswerResult> {
    const reply = await this.#waitForCc(CC_MSG.CONN_REQ, opts.timeoutMs ?? 60000);
    const connReqBytes = reply.message.cc?.bodyBytes;
    if (!connReqBytes) throw new Error("PLANET conn_req missing body");
    const connReq = decodeCcConnReq(connReqBytes);
    const peerAnswerOffer = tryDecodeNativeSetupOffer(connReq.answer);
    const peerOffer = tryDecodeNativeSetupOffer(connReq.offer);
    const mediaReady = await this.#configureMedia(peerAnswerOffer ?? peerOffer, connReq);
    this.#remoteCcChanId = reply.message.cc?.hdr?.srcChanId ?? this.#remoteCcChanId;
    this.#remoteMediaChanId = connReq.mChanId ?? this.#remoteMediaChanId;
    let connRspSent = false;
    if (opts.autoConnRsp ?? true) {
      await this.#sendConnRsp(reply, connReq);
      await this.#sendExchangeAppStrDataInfoReq(reply, connReq);
      this.#autoConnRspDuplicates = true;
      connRspSent = true;
    }
    return {
      plaintext: reply.plaintext,
      message: reply.message,
      connReq,
      peerAnswerOffer,
      peerOffer,
      connRspSent,
      mediaReady,
    };
  }

  waitForAnswer(_opts?: { to: string }): Promise<PlanetAnswerResult> {
    return this.waitForAnswerDetailed();
  }

  async #configureMedia(
    peerOffer: NativeSetupOffer | undefined,
    connReq: CcConnReq,
  ): Promise<boolean> {
    if (!peerOffer) return false;
    const local = this.#localMediaOffer;
    const route = this.#route;
    if (!local || !route) return false;
    this.#debug({
      type: "media_streams",
      streams: peerOffer.media.map(({ name, enabled, kind, kinds, rtpId, rtpPort, rtcpId }) => ({
        name,
        enabled,
        kind,
        kinds,
        rtpId,
        rtpPort,
        rtcpId,
      })),
    });
    this.#mediaKeyCandidates = [];
    const addCandidate = async (
      mode: MediaKeyCandidate["mode"],
      send: string,
      recv: string,
      sendKey: Uint8Array,
      recvKey: Uint8Array,
      streamLabels = false,
    ) => {
      const key = (material: Uint8Array, kind: "AUDIO" | "VIDEO") =>
        streamLabels ? derivePlanetMediaStreamKeying(material, kind) : material;
      this.#mediaKeyCandidates.push({
        mode,
        send,
        recv,
        sendContext: await deriveSrtpContext(key(sendKey, "AUDIO")),
        recvContext: await deriveSrtpContext(key(recvKey, "AUDIO")),
        videoSendContext: await deriveSrtpContext(key(sendKey, "VIDEO")),
        videoRecvContext: await deriveSrtpContext(key(recvKey, "VIDEO")),
      });
    };
    if (peerOffer.mediaPubKey && peerOffer.mediaKeyId !== undefined && peerOffer.mediaNonce) {
      const keyInput = {
        local: {
          privateKey: local.keypair.privateKey,
          publicKey: local.material.mediaPubKey,
          mediaKeyId: local.material.mediaKeyId,
          mediaNonce: local.material.mediaNonce,
        },
        peer: {
          publicKey: peerOffer.mediaPubKey,
          mediaKeyId: peerOffer.mediaKeyId,
          mediaNonce: peerOffer.mediaNonce,
        },
      };
      const variants = derivePlanetMediaKeyingVariants(keyInput);
      for (const selection of Object.values(MEDIA_KEY_SELECTIONS)) {
        const sendKeying = variants.variants[selection.send];
        const recvKeying = variants.variants[selection.recv];
        await addCandidate(selection.mode, selection.send, selection.recv, sendKeying, recvKeying);
        await addCandidate(
          audioMediaKeyMode(selection.mode),
          `AUDIO/${selection.send}`,
          `AUDIO/${selection.recv}`,
          sendKeying,
          recvKeying,
          true,
        );
      }
    }
    if (local.material.mediaSecret.length === 30 && peerOffer.mediaSecret?.length === 30) {
      await addCandidate(
        "secret-receiver",
        "peer-secret",
        "local-secret",
        peerOffer.mediaSecret,
        local.material.mediaSecret,
      );
      await addCandidate(
        "secret-sender",
        "local-secret",
        "peer-secret",
        local.material.mediaSecret,
        peerOffer.mediaSecret,
      );
      await addCandidate(
        "audio-secret-receiver",
        "AUDIO/peer-secret",
        "AUDIO/local-secret",
        peerOffer.mediaSecret,
        local.material.mediaSecret,
        true,
      );
      await addCandidate(
        "audio-secret-sender",
        "AUDIO/local-secret",
        "AUDIO/peer-secret",
        local.material.mediaSecret,
        peerOffer.mediaSecret,
        true,
      );
    }
    if (this.#mediaKeyCandidates.length === 0) return false;
    const requestedMode =
      this.#opts.mediaKeyMode ?? (this.#groupJoined ? "audio-secret-sender" : "auto");
    // Peers can choose either advertised security scheme. Preserve the known
    // ECDH start, then select another candidate only after SRTP authentication.
    const initialMode =
      requestedMode === "auto"
        ? this.#mediaKeyCandidates.some((c) => c.mode === "audio-reverse-stage")
          ? "audio-reverse-stage"
          : "audio-secret-sender"
        : requestedMode;
    const initial = this.#mediaKeyCandidates.find((c) => c.mode === initialMode);
    if (!initial) return false;
    this.#srtpSend = initial.sendContext;
    this.#srtpRecv = initial.recvContext;
    this.#videoSend = initial.videoSendContext;
    this.#videoRecv = initial.videoRecvContext;
    this.#groupDataSrtpSend = undefined;
    this.#groupDataRtp = undefined;
    this.#dataSrtpRecv = undefined;
    if (this.#groupJoined && local.material.mediaSecret.length === 30) {
      this.#groupDataSrtpSend = await deriveSrtpContext(
        derivePlanetMediaStreamKeying(local.material.mediaSecret, "DATA"),
      );
    }
    if (local.material.mediaSecret.length === 30 && peerOffer.mediaSecret?.length === 30) {
      this.#dataSrtpRecv = await deriveSrtpContext(
        derivePlanetMediaStreamKeying(peerOffer.mediaSecret, "DATA"),
      );
    }
    this.#mediaKeyMode = requestedMode;
    const fallbackHost =
      route.mediaHost ??
      (this.#opts.preferIpv6 && route.cscfHost6 ? route.cscfHost6 : route.cscfHost);
    const fallbackPort = route.mediaPort ?? route.cscfPort;
    const mAddrEndpoint = addrEndpoint(connReq.mAddr);
    const publicEndpoint = addrEndpoint(connReq.uePublicAddr);
    const endpoint = mAddrEndpoint ?? publicEndpoint ?? { host: fallbackHost, port: fallbackPort };
    const endpointSource = mAddrEndpoint ? "mAddr" : publicEndpoint ? "uePublicAddr" : "route";
    const audio =
      peerOffer.media.find((m) => m.name === "A" && m.enabled !== 0 && m.rtpId !== undefined) ??
      peerOffer.media.find((m) => m.kind === 1 && m.enabled !== 0 && m.rtpId !== undefined);
    this.#dataPayloadType = peerOffer.media.find((m) => m.name === "D" && m.enabled !== 0)?.rtpId;
    // The answerer's local_srcid is the caller's RX stream. Using the peer's
    // remote_srcid here hits its TX stream and native drops it before decoding.
    const answeredAudio = this.#incomingCall
      ? decodeNativeSetupOffer(local.offer).media.find((m) => m.name === "A")
      : undefined;
    this.#rtp = {
      host: endpoint.host,
      port: endpoint.port,
      payloadType: audio?.rtpId ?? 96,
      ssrc:
        (this.#groupJoined ? this.#groupAudioSsrc : undefined) ??
        (this.#incomingCall ? answeredAudio?.rtpPort : audio?.rtcpId) ??
        audio?.rtpPort ??
        randomU32(),
      seq: randomIntInclusive(0, 0xffff),
      timestamp: 0,
    };
    const videoKinds = this.#groupJoined ? [7, 4] : [2];
    const video = peerOffer.media.find(
      (m) => m.name === "V" && videoKinds.some((kind) => (m.kinds ?? [m.kind]).includes(kind)),
    );
    const localVideo = decodeNativeSetupOffer(local.offer).media.find((m) => m.name === "V");
    if (
      video &&
      localVideo &&
      videoKinds.some((kind) => localVideo?.kinds?.includes(kind)) &&
      (!this.#groupJoined ||
        video.features?.some((feature) => feature.id === 2 && feature.version === 1)) &&
      video.rtpId !== undefined &&
      video.rtpId > 0 &&
      video.rtpId < 128 &&
      video.rtpId !== this.#rtp.payloadType &&
      video.rtpPort !== undefined &&
      video.rtcpId !== undefined
    ) {
      this.#videoRtp = {
        payloadType: video.rtpId,
        ssrc: this.#incomingCall ? localVideo.rtpPort! : video.rtcpId,
        recvSsrc: this.#incomingCall ? localVideo.rtcpId! : video.rtpPort,
        seq: randomIntInclusive(0, 0xffff),
        pictureId: 0,
      };
    }
    if (this.#initialVideo && !this.#videoRtp) throw new Error("Peer does not support VP8 video");
    if (this.#groupDataSrtpSend) {
      this.#groupDataRtp = {
        ssrc: this.#groupDataSsrc!,
        number: 1n,
      };
    }
    this.#debug({
      type: "media_configured",
      endpoint: endpointSource,
      family: endpoint.host.includes(":") ? "ipv6" : "ipv4",
      port: endpoint.port,
      payloadType: this.#rtp.payloadType,
      ssrc: this.#rtp.ssrc,
      rtcpId: audio?.rtcpId,
      rtpPort: audio?.rtpPort,
      groupDataSsrc: this.#groupDataRtp?.ssrc,
      mediaKeyMode: requestedMode,
      activeMediaKeyMode: initial.mode,
    });
    return true;
  }

  async #sendConnRsp(
    request: PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    },
    connReq: CcConnReq,
  ): Promise<void> {
    const ccBody = wrapCcMsg(
      CC_MSG.CONN_RSP,
      packCcConnRsp({
        result: 0,
        mChanId: this.#localMediaChanId,
        netType: connReq.netType ?? 1,
        unavailToSec: connReq.unavailToSec ?? 120,
        ua: packPlanetUserAgent(
          this.#opts.userAgent ?? defaultAndroidUserAgent(this.#opts.deviceInfo),
        ),
        svcId: connReq.svcId,
        tgtSvcId: connReq.tgtSvcId,
        interDomain: connReq.interDomain,
      }),
    );
    const ccMsg = packPlanetCcMsg(
      {
        cid: request.message.cc?.hdr?.cid ?? this.#callUuid ?? "conn-rsp",
        srcChanId: this.#srcChanId,
        dstChanId: request.message.cc?.hdr?.srcChanId ?? 0n,
      },
      ccBody,
    );
    await this.#sendEnvelope(
      { kind: "cc", data: ccMsg },
      {
        msgId: ccMsgId(CC_MSG.CONN_RSP),
        tranId: request.message.hdr?.tranId,
        tranSeq: request.message.hdr?.tranSeq,
        rmtNonce: request.message.hdr?.locNonce,
      },
    );
  }

  async #sendExchangeAppStrDataInfoReq(
    request: PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    },
    connReq: CcConnReq,
  ): Promise<void> {
    const targetMid = this.#targetMid;
    if (!targetMid) {
      this.#debug({ type: "info_req_skipped", reason: "missing_target" });
      return;
    }
    const body = new TextEncoder().encode('{"csv":1}\0');
    const ccBody = wrapCcMsg(
      CC_MSG.INFO_REQ,
      packCcInfoReq({
        bodyType: "exchange_app_str_data",
        body,
        targets: [],
        source: this.#opts.localMid,
        tgtUe: [packPlanetUeInfo({ userId: targetMid })],
        svcId: connReq.svcId,
        tgtSvcId: connReq.tgtSvcId,
        interDomain: connReq.interDomain,
      }),
    );
    const ccMsg = packPlanetCcMsg(
      {
        cid: request.message.cc?.hdr?.cid ?? this.#callUuid ?? "info-req",
        srcChanId: this.#srcChanId,
        dstChanId: request.message.cc?.hdr?.srcChanId ?? this.#remoteCcChanId,
      },
      ccBody,
    );
    await this.#sendEnvelope({ kind: "cc", data: ccMsg }, { msgId: ccMsgId(CC_MSG.INFO_REQ) });
    this.#debug({ type: "info_req_exchange_app_str_data" });
  }

  async #sendMcDataRsp(
    request: PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    },
  ): Promise<void> {
    const bodyBytes = request.message.mc?.bodyBytes;
    if (!bodyBytes) return;
    const dataReq = decodeMcDataReq(bodyBytes);
    let responseData = defaultOneToOneDataSessionPayload();
    if (dataReq.dispatchId === 2 && dataReq.data && dataReq.data.length >= 8) {
      const control = decodeMcStreamControl(dataReq.data);
      if (control) {
        const video = this.#videoRtp;
        const supported = control.mediaKind === 2 && video;
        const known = supported
          ? control.ssrcs.filter((id) => id === video.ssrc || id === video.recvSsrc)
          : [];
        responseData = packMcStreamControl({
          ...control,
          code: supported ? 0 : 203,
          ssrcs: control.operation === 1 ? known : control.ssrcs,
        });
        if (supported && known.includes(video.recvSsrc)) {
          const enabled = control.operation === 1 || control.operation === 4;
          if (!enabled) this.#videoAssembler.clear();
          this.onVideoState?.(enabled);
          this.#debug({ type: "video_remote_state", enabled, operation: control.operation });
        }
      }
    }
    const dataRsp = packMcDataRsp({
      result: 0,
      relCode: 0,
      dispatchId: dataReq.dispatchId,
      data: responseData,
    });
    const mcBody = wrapMcMsg(MC_MSG.DATA_RSP, dataRsp);
    const mcMsg = packPlanetMcMsg(
      {
        cid: request.message.mc?.hdr?.cid ?? this.#callUuid ?? "mc-data-rsp",
        srcChanId: this.#localMediaChanId,
        dstChanId: request.message.mc?.hdr?.srcChanId ?? this.#remoteMediaChanId,
      },
      mcBody,
    );
    this.#debug({
      type: "mc_data_rsp_sent",
      bodyBytes: dataRsp.length,
      dispatchId: dataReq.dispatchId,
      dstChanIdBits: (request.message.mc?.hdr?.srcChanId ?? this.#remoteMediaChanId).toString(2)
        .length,
    });
    await this.#sendEnvelope(
      { kind: "mc", data: mcMsg },
      {
        msgId: CASSINI_MSG_ID_MC_DATA_RSP,
        tranId: request.message.hdr?.tranId,
        tranSeq: request.message.hdr?.tranSeq,
        rmtNonce: request.message.hdr?.locNonce,
      },
    );
  }

  async #sendMcJoinRsp(
    request: PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    },
  ): Promise<void> {
    const rsp = packMcJoinRsp({
      result: 0,
      data: defaultOneToOneStrmSpec(),
    });
    const mcBody = wrapMcMsg(MC_MSG.JOIN_RSP, rsp);
    const mcMsg = packPlanetMcMsg(
      {
        cid: request.message.mc?.hdr?.cid ?? this.#callUuid ?? "mc-join-rsp",
        srcChanId: this.#localMediaChanId,
        dstChanId: request.message.mc?.hdr?.srcChanId ?? this.#remoteMediaChanId,
      },
      mcBody,
    );
    this.#debug({ type: "mc_join_rsp_sent" });
    await this.#sendEnvelope(
      { kind: "mc", data: mcMsg },
      {
        msgId: CASSINI_MSG_ID_MC_JOIN_RSP,
        tranId: request.message.hdr?.tranId,
        tranSeq: request.message.hdr?.tranSeq,
        rmtNonce: request.message.hdr?.locNonce,
      },
    );
    void this.#sendBepiChannelOpen().catch(() => {});
    void this.#sendMcCheckRpt(request).catch(() => {});
  }

  async #sendMcChangeRsp(
    request: PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    },
  ): Promise<void> {
    const rsp = packMcChangeRsp({
      result: 0,
      data: defaultOneToOneStrmSpec(),
    });
    const mcBody = wrapMcMsg(MC_MSG.CHANGE_RSP, rsp);
    const mcMsg = packPlanetMcMsg(
      {
        cid: request.message.mc?.hdr?.cid ?? this.#callUuid ?? "mc-change-rsp",
        srcChanId: this.#localMediaChanId,
        dstChanId: request.message.mc?.hdr?.srcChanId ?? this.#remoteMediaChanId,
      },
      mcBody,
    );
    this.#debug({ type: "mc_change_rsp_sent" });
    await this.#sendEnvelope(
      { kind: "mc", data: mcMsg },
      {
        msgId: CASSINI_MSG_ID_MC_CHANGE_RSP,
        tranId: request.message.hdr?.tranId,
        tranSeq: request.message.hdr?.tranSeq,
        rmtNonce: request.message.hdr?.locNonce,
      },
    );
  }

  async #sendMcCheckRpt(
    request: PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    },
  ): Promise<void> {
    const rpt = packMcCheckRpt(defaultOneToOneStrmSpec());
    const mcBody = wrapMcMsg(MC_MSG.CHECK_RPT, rpt);
    const mcMsg = packPlanetMcMsg(
      {
        cid: request.message.mc?.hdr?.cid ?? this.#callUuid ?? "mc-check-rpt",
        srcChanId: this.#localMediaChanId,
        dstChanId: request.message.mc?.hdr?.srcChanId ?? this.#remoteMediaChanId,
      },
      mcBody,
    );
    this.#debug({ type: "mc_check_rpt_sent" });
    await this.#sendEnvelope({ kind: "mc", data: mcMsg }, { msgId: CASSINI_MSG_ID_MC_CHECK_RPT });
  }

  async #sendBepiChannelOpen(): Promise<void> {
    const token = BigInt(
      "0x" +
        Array.from(crypto.getRandomValues(new Uint8Array(8)))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
    );
    const data = packBepiChannelOpen(token);
    this.#debug({ type: "bepi_channel_open_sent" });
    await this.#sendEnvelope({ kind: "sc", data }, { msgId: CASSINI_MSG_ID_BEPI_OPEN });
  }

  async #sendDuplicateConnRsp(
    request: PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    },
  ): Promise<void> {
    if (!this.#autoConnRspDuplicates || this.#connRspDuplicateInFlight) {
      return;
    }
    const bodyBytes = request.message.cc?.bodyBytes;
    if (!bodyBytes) return;
    this.#connRspDuplicateInFlight = true;
    try {
      const connReq = decodeCcConnReq(bodyBytes);
      if (!this.#srtpSend || !this.#rtp) {
        const peerAnswerOffer = tryDecodeNativeSetupOffer(connReq.answer);
        const peerOffer = tryDecodeNativeSetupOffer(connReq.offer);
        await this.#configureMedia(peerAnswerOffer ?? peerOffer, connReq);
      }
      await this.#sendConnRsp(request, connReq);
      this.#debug({ type: "conn_rsp_duplicate" });
    } finally {
      this.#connRspDuplicateInFlight = false;
    }
  }

  async #sendInfoRsp(
    request: PlanetIncomingMessage & {
      message: ReturnType<typeof decodePlanetMsg>;
    },
  ): Promise<void> {
    const bodyBytes = request.message.cc?.bodyBytes;
    if (!bodyBytes) return;
    let infoReq: ReturnType<typeof decodeCcInfoReq>;
    try {
      infoReq = decodeCcInfoReq(bodyBytes);
    } catch {
      return;
    }
    const ccBody = wrapCcMsg(
      CC_MSG.INFO_RSP,
      packCcInfoRsp({
        result: 0,
        bodyType: infoReq.bodyType,
        body: infoReq.body,
        svcId: infoReq.svcId,
        tgtSvcId: infoReq.tgtSvcId,
        interDomain: infoReq.interDomain,
      }),
    );
    const ccMsg = packPlanetCcMsg(
      {
        cid: request.message.cc?.hdr?.cid ?? this.#callUuid ?? "info-rsp",
        srcChanId: this.#srcChanId,
        dstChanId: request.message.cc?.hdr?.srcChanId ?? 0n,
      },
      ccBody,
    );
    await this.#sendEnvelope(
      { kind: "cc", data: ccMsg },
      {
        msgId: ccMsgId(CC_MSG.INFO_RSP),
        tranId: request.message.hdr?.tranId,
        tranSeq: request.message.hdr?.tranSeq,
        rmtNonce: request.message.hdr?.locNonce,
      },
    );
  }

  #clearKeepalive() {
    if (this.#keepaliveTimer !== undefined) {
      clearTimeout(this.#keepaliveTimer);
      this.#keepaliveTimer = undefined;
    }
  }

  #startKeepalive(aliveRptIntervalSec: number | undefined) {
    this.#clearKeepalive();
    const configured = this.#opts.keepaliveIntervalMs;
    const intervalMs =
      configured ??
      (aliveRptIntervalSec && aliveRptIntervalSec > 0 ? aliveRptIntervalSec * 1000 : undefined);
    if (!intervalMs || intervalMs <= 0) {
      this.#debug({ type: "keepalive_disabled" });
      return;
    }
    this.#debug({ type: "keepalive_scheduled", intervalMs });
    const delayMs = Math.max(10, Math.floor(intervalMs));
    const tick = () => {
      if (this.#closed) return;
      void this.#sendKeepalive()
        .catch(() => {})
        .finally(() => {
          if (!this.#closed) this.#keepaliveTimer = setTimeout(tick, delayMs);
        });
    };
    this.#keepaliveTimer = setTimeout(tick, delayMs);
  }

  async #sendKeepalive(): Promise<void> {
    const inner = packKeepaliveReq(BigInt(Date.now()), false);
    await this.#sendEnvelope(
      {
        kind: "sc",
        data: packPlanetScMsgKaReq(inner),
      },
      { msgId: CASSINI_MSG_ID_KEEPALIVE_REQ },
    );
  }

  async #sendCcResult(
    request: PlanetIncomingMessage & { message: ReturnType<typeof decodePlanetMsg> },
    bodyTag: typeof CC_MSG.REL_RSP | typeof CC_MSG.PUSH_RSP,
  ): Promise<void> {
    const cc = packPlanetCcMsg(
      {
        cid: request.message.cc!.hdr!.cid!,
        srcChanId: this.#srcChanId,
        dstChanId: request.message.cc?.hdr?.srcChanId ?? 0n,
      },
      wrapCcMsg(bodyTag, packVarintField(1, 0)),
    );
    await this.#sendEnvelope(
      { kind: "cc", data: cc },
      {
        msgId: ccMsgId(bodyTag),
        tranId: request.message.hdr?.tranId,
        tranSeq: request.message.hdr?.tranSeq,
        rmtNonce: request.message.hdr?.locNonce,
      },
    );
  }

  /**
   * Peer-initiated release (REL_REQ). Acknowledge before closing the socket;
   * never echo another REL_REQ. Drains RTP waiters so
   * receive() terminates, and fails pending control waiters so an in-flight
   * invite()/answer() surfaces the hangup instead of timing out.
   */
  async #handleRemoteRelease(
    request: PlanetIncomingMessage & { message: ReturnType<typeof decodePlanetMsg> },
    info: { relCode?: number; relPhrase?: string; releaser?: string },
  ): Promise<void> {
    if (this.#remoteEnded) return;
    this.#remoteEnded = true;
    this.#setupSent = false;
    this.#rtpQueue = [];
    this.#pdtp = new PdtpReceiver();
    this.#conference = new ConferenceState();
    const who = [info.releaser, info.relPhrase].filter(Boolean).join(":");
    const code = typeof info.relCode === "number" ? ` (relCode=${info.relCode})` : "";
    this.#remoteEndReason = `remote ended the call${code}${who ? `: ${who}` : ""}`;
    this.#debug({
      type: "rel_remote_end",
      relCode: info.relCode,
      relPhrase: info.relPhrase,
      releaser: info.releaser,
    });
    this.#closed = true;
    this.#clearKeepalive();
    this.#clearVideo();
    await this.#sendCcResult(request, CC_MSG.REL_RSP).catch(() => {});
    if (this.#sock) {
      const sock = this.#sock;
      this.#sock = undefined;
      try {
        sock.close(() => {});
      } catch {
        /* */
      }
    }
    const err = new Error(this.#remoteEndReason);
    for (const waiter of this.#rtpWaiters.splice(0)) waiter(null);
    for (const waiter of this.#pending.splice(0)) waiter(err);
  }

  async close(): Promise<void> {
    this.#closed = true;
    this.#clearVideo();
    this.#clearKeepalive();
    this.#pdtp = new PdtpReceiver();
    this.#conference = new ConferenceState();
    try {
      if (this.#setupSent && this.#route && (this.#sock || this.#opts.wireSend)) {
        this.#setupSent = false;
        const relBody = this.#route.groupToken
          ? packCcRelReq({
              relCode: 1,
              releaser: "participant",
              commMediaFlags: 1,
              dataSvcs: [0],
              roomDestroy: false,
            })
          : packCcRelReq({
              relCode: 2,
              releaser: this.#incomingCall ? "responder" : "initiator",
              commMediaFlags: 1,
            });
        const ccBody = wrapCcMsg(CC_MSG.REL_REQ, relBody);
        const ccMsg = packPlanetCcMsg(
          {
            cid: this.#callUuid ?? "rel",
            srcChanId: this.#srcChanId,
            dstChanId: this.#remoteCcChanId,
          },
          ccBody,
        );
        await this.#sendEnvelope({ kind: "cc", data: ccMsg }, { msgId: CASSINI_MSG_ID_REL_REQ });
      }
    } catch {
      /* */
    }
    if (this.#sock) {
      await new Promise<void>((res) => this.#sock!.close(() => res()));
      this.#sock = undefined;
    }
    for (const waiter of this.#rtpWaiters.splice(0)) waiter(null);
    for (const waiter of this.#pending.splice(0)) waiter(new Error("transport closed"));
  }

  async send(
    opusPacket: Uint8Array,
    opts: { timestampStep?: number; audioLevel?: number } = {},
  ): Promise<void> {
    if (!this.#srtpSend || !this.#rtp) {
      throw new Error("PlanetTransport.send: media not established");
    }
    let payload: Uint8Array;
    let extensionData: Uint8Array | undefined;
    let timestampStep = opts.timestampStep ?? this.#opts.rtpTimestampStep ?? 960;
    if (this.#groupJoined) {
      // Encode 20ms frames; the declared group stream ptime is 40ms.
      packetizeEas2(opusPacket); // Validate before buffering.
      if (
        opts.audioLevel !== undefined &&
        (!Number.isInteger(opts.audioLevel) || opts.audioLevel < 0 || opts.audioLevel > 127)
      )
        throw new Error("Invalid group audio level");
      this.#pendingGroupAudio.push({
        opus: opusPacket.slice(),
        audio:
          opts.audioLevel === undefined
            ? undefined
            : { level: opts.audioLevel, signal: this.#groupActivity.signal(opts.audioLevel) },
      });
      if (this.#pendingGroupAudio.length < 2) return;
      payload = packetizeEas2Frames(this.#pendingGroupAudio.map((f) => f.opus));
      const frames = this.#pendingGroupAudio.map((f) => f.audio);
      if (frames.every((n) => n !== undefined))
        extensionData = buildGroupVsd([frames[0]!, frames[1]!]);
      this.#pendingGroupAudio = [];
      timestampStep = 1920;
    } else payload = packetizeEas2(opusPacket);
    const timestamp = (this.#rtp.timestamp += timestampStep) >>> 0;
    const seq = this.#rtp.seq++ & 0xffff;
    const rtp = buildRtp({
      payloadType: this.#rtp.payloadType,
      marker: !this.#audioSent,
      seq,
      timestamp,
      ssrc: this.#rtp.ssrc,
      payload,
      extensionProfile: 0x0240,
      extensionData,
    });
    const wire = await srtpEncrypt(this.#srtpSend, rtp);
    this.#audioSent = true;
    this.#debug({
      type: "media_send",
      bytes: wire.length,
      payloadBytes: payload.length,
      firstByte: payload[0],
      payloadType: this.#rtp.payloadType,
      marker: (rtp[1] & 0x80) !== 0,
      ssrc: this.#rtp.ssrc,
      seq,
      rtpFirstByte: rtp[0],
      rtpExtensionBytes: extensionData?.length ?? 0,
      timestamp,
      timestampStep,
      family: this.#rtp.host.includes(":") ? "ipv6" : "ipv4",
      port: this.#rtp.port,
    });
    if (this.#opts.wireSend) {
      await this.#opts.wireSend(wire, {
        host: this.#rtp.host,
        port: this.#rtp.port,
        bootstrap: false,
        seq: this.#rtp.seq,
        plainLen: payload.length,
        bodyLen: wire.length,
        plaintext: payload,
      });
      return;
    }
    if (!this.#sock) throw new Error("PlanetTransport.send: socket closed");
    await new Promise<void>((res, rj) =>
      this.#sock!.send(Buffer.from(wire), this.#rtp!.port, this.#rtp!.host, (e) =>
        e ? rj(e) : res(),
      ),
    );
  }

  async #sendGroupPdtp(reply: Omit<PdtpPacket, "number">, channel: number): Promise<void> {
    if (this.#closed || !this.#groupDataRtp || !this.#groupDataSrtpSend || !this.#rtp) return;
    const number = this.#groupDataRtp.number++;
    const payload = buildPdtp({ ...reply, number });
    const extensionData = channel ? new Uint8Array(4) : undefined;
    if (extensionData) new DataView(extensionData.buffer).setUint32(0, channel);
    const rtp = buildRtp({
      payloadType: this.#dataPayloadType!,
      ssrc: this.#groupDataRtp.ssrc,
      seq: Number(number & 65535n),
      timestamp: Math.floor(performance.now()) >>> 0,
      payload,
      extensionProfile: channel ? 0x0261 : 0x0240,
      extensionData,
    });
    const wire = await srtpEncrypt(this.#groupDataSrtpSend, rtp);
    if (this.#closed) return;
    if (this.#opts.wireSend)
      await this.#opts.wireSend(wire, {
        host: this.#rtp.host,
        port: this.#rtp.port,
        bootstrap: false,
        seq: Number(number & 65535n),
        plainLen: payload.length,
        bodyLen: wire.length,
        plaintext: payload,
      });
    else {
      const sock = this.#sock;
      if (!sock) return;
      await new Promise<void>((resolve, reject) =>
        sock.send(wire, this.#rtp!.port, this.#rtp!.host, (error) =>
          error ? reject(error) : resolve(),
        ),
      );
    }
  }

  #emitConference(): void {
    const members = this.#conference.members;
    const sources = new Map(
      members
        .filter((m) => m.mid !== this.#opts.localMid)
        .flatMap((m) =>
          m.sources.filter((s) => s.name === "V").map((s) => [s.ssrc, m.mid] as const),
        ),
    );
    for (const [ssrc, stream] of this.#groupVideoAssemblers) {
      if (
        sources.get(ssrc) !== this.#groupVideoSources.get(ssrc) ||
        this.#pausedGroupVideo.has(ssrc)
      ) {
        stream.assembler.clear();
        this.#groupVideoAssemblers.delete(ssrc);
      }
    }
    for (const ssrc of this.#groupVideoSources.keys()) {
      if (sources.get(ssrc) !== this.#groupVideoSources.get(ssrc)) {
        this.#pausedGroupVideo.delete(ssrc);
        this.#notifiedVideoChannels.delete(ssrc);
      }
    }
    for (const [ssrc, channel] of this.#notifiedVideoChannels)
      if (this.#conference.hasChannel(channel)) this.#notifiedVideoChannels.delete(ssrc);
    this.#groupVideoSources = sources;
    this.#debug({
      type: "group_conference",
      members: members.length,
      sources: members.reduce((n, m) => n + m.sources.length, 0),
    });
    this.onConference?.(
      members.map((member) => ({
        ...member,
        sources: member.sources.filter(
          (source) => source.name !== "V" || !this.#pausedGroupVideo.has(source.ssrc),
        ),
      })),
    );
    this.#syncGroupVideoSubscriptions();
  }

  #syncGroupVideoSubscriptions(): void {
    this.#subscriptionDirty = true;
    if (
      this.#subscriptionSync ||
      !this.#groupJoined ||
      !this.#groupDataSessionSent ||
      !this.videoAvailable
    )
      return;
    const generation = this.#subscriptionGeneration;
    this.#subscriptionSync = (async () => {
      while (
        this.#subscriptionDirty &&
        !this.#closed &&
        generation === this.#subscriptionGeneration
      ) {
        this.#subscriptionDirty = false;
        const desired = new Map<number, { mid: string; channel: number }>();
        for (const source of this.#conference.videoSources) {
          if (source.mid !== this.#opts.localMid && !desired.has(source.ssrc) && desired.size < 30)
            desired.set(source.ssrc, { mid: source.mid, channel: source.channel });
        }
        for (const [ssrc, channel] of this.#notifiedVideoChannels) {
          const mid = this.#groupVideoSources.get(ssrc);
          if (mid && !desired.has(ssrc) && desired.size < 30) desired.set(ssrc, { mid, channel });
        }
        const requests: Array<{ ssrc: number; channel: number; start: boolean }> = [];
        for (const [ssrc, old] of this.#groupVideoSubscriptions) {
          const next = desired.get(ssrc);
          if (next?.channel !== old.channel || next.mid !== old.mid)
            requests.push({ ssrc, channel: old.channel, start: false });
        }
        for (const [ssrc, next] of desired) {
          const old = this.#groupVideoSubscriptions.get(ssrc);
          if (old?.channel !== next.channel || old.mid !== next.mid)
            requests.push({ ssrc, channel: next.channel, start: true });
        }
        if (!requests.length) continue;
        const tranId = newSessionId();
        const acknowledgement = new Promise<void>((resolve, reject) => {
          this.#subscriptionControl = { tranId, resolve, reject };
        });
        const pending = this.#subscriptionControl!;
        const timeout = setTimeout(
          () => pending.reject(new Error("Group video subscription timed out")),
          5000,
        );
        try {
          const mc = packPlanetMcMsg(
            {
              cid: this.#negotiatedCallId ?? this.#callUuid!,
              srcChanId: this.#localMediaChanId,
              dstChanId: this.#remoteMediaChanId,
            },
            wrapMcMsg(MC_MSG.STRM_REQ, packMcStrmReq(this.#subscriptionSequence++ >>> 0, requests)),
          );
          await Promise.all([
            this.#sendEnvelope({ kind: "mc", data: mc }, { msgId: 0x318d, tranId }),
            acknowledgement,
          ]);
          if (this.#closed || generation !== this.#subscriptionGeneration) return;
          this.#groupVideoSubscriptions = desired;
        } finally {
          clearTimeout(timeout);
          if (this.#subscriptionControl === pending) this.#subscriptionControl = undefined;
        }
      }
    })()
      .catch(() => {
        this.#debug({ type: "group_video_subscription_failed" });
      })
      .finally(() => {
        if (generation !== this.#subscriptionGeneration) return;
        this.#subscriptionSync = undefined;
        if (this.#subscriptionDirty && !this.#closed) this.#syncGroupVideoSubscriptions();
      });
  }

  #clearVideo(): void {
    this.#groupVideoRequested = false;
    this.#groupVideoNeedsKey = true;
    this.#groupVideoCodec = 3;
    this.#subscriptionGeneration++;
    this.#subscriptionControl?.reject(new Error("Video call ended"));
    this.#subscriptionControl = undefined;
    this.#subscriptionSync = undefined;
    this.#subscriptionDirty = false;
    this.#subscriptionSequence = 0;
    this.#groupVideoSubscriptions.clear();
    this.#pausedGroupVideo.clear();
    this.#notifiedVideoChannels.clear();
    this.#videoControl?.reject(new Error("Video call ended"));
    this.#videoControl = undefined;
    this.#videoEnabled = false;
    this.#videoStarted = false;
    this.#videoRtp = undefined;
    this.#videoSend = undefined;
    this.#videoRecv = undefined;
    this.#videoQueue = [];
    this.#videoAssembler.clear();
    for (const stream of this.#groupVideoAssemblers.values()) stream.assembler.clear();
    this.#groupVideoAssemblers.clear();
    this.#groupVideoSources.clear();
    for (const waiter of this.#videoWaiters.splice(0)) waiter(null);
  }

  async setVideoEnabled(enabled: boolean): Promise<void> {
    const video = this.#videoRtp;
    if (!this.videoAvailable || !video) throw new Error("Video is unavailable for this call");
    if (this.#videoEnabled === enabled) return;
    if (this.#videoControl) throw new Error("Video control pending");
    const firstStart = enabled && !this.#videoStarted;
    const data = packMcStreamControl({
      operation: firstStart ? 1 : enabled ? 4 : 3,
      mediaKind: 2,
      code: 0,
      ssrcs: firstStart && !this.#groupJoined ? [video.ssrc, video.recvSsrc] : [video.ssrc],
    });
    const request = wrapMcMsg(
      MC_MSG.DATA_REQ,
      packMcDataReq({ srcType: 0, dstType: 0, dispatchId: 2, data }),
    );
    const mc = packPlanetMcMsg(
      {
        cid: this.#callUuid,
        srcChanId: this.#localMediaChanId,
        dstChanId: this.#remoteMediaChanId,
      },
      request,
    );
    const tranId = newSessionId();
    const acknowledgement = new Promise<Uint8Array | undefined>((resolve, reject) => {
      this.#videoControl = { tranId, resolve, reject };
    });
    const timeout = setTimeout(
      () => this.#videoControl?.reject(new Error("Video control timed out")),
      5000,
    );
    try {
      const [, reply] = await Promise.all([
        this.#sendEnvelope({ kind: "mc", data: mc }, { msgId: CASSINI_MSG_ID_MC_DATA_REQ, tranId }),
        acknowledgement,
      ]);
      const response = reply ? decodeMcStreamControl(reply) : undefined;
      if (
        !response ||
        response.code !== 0 ||
        response.mediaKind !== 2 ||
        response.operation !== (firstStart ? 1 : enabled ? 4 : 3) ||
        !response.ssrcs.includes(video.ssrc)
      ) {
        throw new Error("Peer rejected video control");
      }
    } finally {
      clearTimeout(timeout);
      this.#videoControl = undefined;
    }
    if (this.#closed) return;
    this.#videoEnabled = enabled;
    if (!enabled && this.#videoRtp) {
      this.#videoRtp.resolution = undefined;
      this.#groupVideoNeedsKey = true;
    }
    if (enabled) this.#videoStarted = true;
    this.#debug({ type: "video_local_state", enabled });
  }

  async sendVideo(frame: EncodedVideoFrame): Promise<void> {
    const video = this.#videoRtp;
    const cryptoContext = this.#videoSend;
    if (!this.#videoEnabled || this.#closed || !video || !cryptoContext || !this.#rtp) {
      throw new Error("Video is not enabled");
    }
    if (!Number.isInteger(frame.timestamp) || frame.timestamp < 0 || frame.timestamp > 0xffffffff) {
      throw new Error("Invalid video timestamp");
    }
    const pictureId = video.pictureId++ & 0xffff;
    let packets: Array<{ payload: Uint8Array; extensionData?: Uint8Array }>;
    const frameCodec = this.#groupVideoCodec;
    if (this.#groupJoined) {
      if (!this.#groupVideoRequested) return;
      const codec = this.#groupVideoCodec;
      if (codec === undefined) throw new Error("Requested group video codec is unsupported");
      if (this.#groupVideoNeedsKey && !frame.key) return;
      validateVp8(frame.data, frame.key);
      if (frame.key) {
        // Native 0x17bed0 classifies by coded area, not aspect ratio (0x13515d0).
        const area =
          (frame.data[6] | ((frame.data[7] & 63) << 8)) *
          (frame.data[8] | ((frame.data[9] & 63) << 8));
        video.resolution = area <= 19200 ? 0 : area <= 172800 ? 1 : area <= 691200 ? 2 : 3;
      }
      if (video.resolution === undefined) throw new Error("Group video needs a key frame");
      packets = packetizeSvcVp8(
        frame.data,
        frame.key,
        pictureId,
        video.seq & 0xffff,
        video.resolution,
        1000,
        codec,
      );
    } else
      packets = packetizeEvs3(frame.data, frame.key, pictureId).map((payload) => ({ payload }));
    for (let i = 0; i < packets.length; i++) {
      if (!this.#videoEnabled || this.#closed || (this.#groupJoined && !this.#groupVideoRequested))
        return;
      const rtp = buildRtp({
        payloadType: video.payloadType,
        ssrc: video.ssrc,
        seq: video.seq++ & 0xffff,
        timestamp: frame.timestamp,
        marker: i === packets.length - 1,
        payload: packets[i].payload,
        ...(this.#groupJoined ? { extensionProfile: 0x0200, extensionData: packets[i].extensionData } : {}),
      });
      const wire = await srtpEncrypt(cryptoContext, rtp);
      if (this.#opts.wireSend) {
        await this.#opts.wireSend(wire, {
          host: this.#rtp.host,
          port: this.#rtp.port,
          bootstrap: false,
          seq: video.seq,
          plainLen: packets[i].payload.length,
          bodyLen: wire.length,
          plaintext: packets[i].payload,
        });
      } else {
        if (!this.#sock || this.#closed) return;
        await new Promise<void>((resolve, reject) =>
          this.#sock!.send(wire, this.#rtp!.port, this.#rtp!.host, (error) =>
            error ? reject(error) : resolve(),
          ),
        );
      }
    }
    if (this.#groupJoined && frame.key && this.#groupVideoCodec === frameCodec)
      this.#groupVideoNeedsKey = false;
    this.#debug({
      type: "video_send",
      bytes: frame.data.length,
      packets: packets.length,
      key: frame.key,
    });
  }

  async *receiveVideo(): AsyncIterable<EncodedVideoFrame> {
    if (!this.videoAvailable) return;
    while (!this.#closed) {
      const datagram =
        this.#videoQueue.shift() ??
        (await new Promise<RtpDatagram | null>((resolve) => this.#videoWaiters.push(resolve)));
      if (!datagram || this.#closed) return;
      try {
        if (!this.#videoRecv || !this.#videoRtp) return;
        let decrypted: Uint8Array | undefined;
        try {
          decrypted = await srtpDecrypt(this.#videoRecv, datagram.packet);
        } catch {
          if (this.#mediaKeyMode !== "auto") throw new Error("Video SRTP auth failed");
          for (const candidate of this.#mediaKeyCandidates) {
            if (candidate.videoRecvContext === this.#videoRecv) continue;
            try {
              decrypted = await srtpDecrypt(candidate.videoRecvContext, datagram.packet);
            } catch {
              continue;
            }
            this.#videoSend = candidate.videoSendContext;
            this.#videoRecv = candidate.videoRecvContext;
            this.#srtpSend = candidate.sendContext;
            this.#srtpRecv = candidate.recvContext;
            this.#debug({ type: "media_key_selected", mode: candidate.mode, media: "VIDEO" });
            break;
          }
        }
        if (!decrypted) throw new Error("Video SRTP auth failed");
        const rtp = parseRtp(decrypted);
        if (rtp.payloadType !== this.#videoRtp.payloadType) continue;
        let assembler = this.#videoAssembler;
        let sourceMid: string | undefined;
        let packet = rtp;
        if (this.#groupJoined) {
          sourceMid = this.#groupVideoSources.get(rtp.ssrc);
          if (!sourceMid || this.#pausedGroupVideo.has(rtp.ssrc)) continue;
          const extension = readPlanetRtpExtension(rtp);
          if (!extension) continue;
          const pd = parseEvs3(rtp.payload, true);
          const normalized = unwrapSvcVp8(rtp.payload);
          let stream = this.#groupVideoAssemblers.get(rtp.ssrc);
          if (!stream) {
            if (this.#groupVideoAssemblers.size >= 30) continue;
            stream = {
              assembler: new Evs3Assembler((reason) =>
                this.#debug({ type: "video_ignored", reason }),
              ),
            };
            this.#groupVideoAssemblers.set(rtp.ssrc, stream);
          }
          if (pd.begin) {
            stream.receivingSpatialId = pd.spatialId;
            if (pd.key && stream.spatialId === undefined) stream.spatialId = pd.spatialId;
          }
          // ponytail: one spatial stream per source, all its temporal frames.
          // Keep strict RTP gaps; add per-layer sequencing before supporting interleaved SID switching.
          if (stream.spatialId === undefined || stream.receivingSpatialId !== stream.spatialId) {
            stream.assembler.clear();
            continue;
          }
          packet = {
            ...rtp,
            seq: parseSvcVfd(extension.elements, rtp.payload, true) ?? rtp.seq,
            payload: normalized,
          };
          assembler = stream.assembler;
        } else if (rtp.ssrc !== this.#videoRtp.recvSsrc) continue;
        this.#updateRtpEndpointFromSource(datagram.source);
        const frame = assembler.push(packet);
        if (frame) {
          this.#debug({ type: "video_recv", bytes: frame.data.length, key: frame.key });
          yield sourceMid ? { ...frame, sourceMid } : frame;
        }
      } catch (error) {
        this.#debug({
          type: "video_ignored",
          reason: error instanceof Error ? error.message : "invalid_media",
        });
      }
    }
  }

  async *receive(): AsyncIterable<Uint8Array> {
    for await (const packet of this.receiveAudio()) yield* packet.frames;
  }

  async *receiveAudio(): AsyncIterable<CallAudioPacket> {
    if (!this.#srtpRecv) {
      throw new Error("PlanetTransport.receive: media not established");
    }
    while (true) {
      const datagram = await this.#takeRtp();
      if (!datagram) return;
      const { packet: wire, source } = datagram;
      try {
        if (this.#groupJoined && (wire[1] & 0x7f) === this.#dataPayloadType) {
          if (!this.#dataSrtpRecv) throw new Error("Group DATA crypto unavailable");
          const data = parseRtp(await srtpDecrypt(this.#dataSrtpRecv, wire));
          const extension = readPlanetRtpExtension(data);
          const channel = extension?.channel ?? 0;
          this.#debug({
            type: "group_data_recv",
            bytes: wire.length,
            payloadBytes: data.payload.length,
            payloadType: data.payloadType,
            channel,
            sameEndpoint: source
              ? source.host === this.#rtp?.host && source.port === this.#rtp?.port
              : undefined,
            sourcePort: source?.port,
            currentPort: this.#rtp?.port,
          });
          const pdtp = parsePdtp(data.payload, data.seq);
          this.#debug({
            type: "group_pdtp_recv",
            serviceKind:
              pdtp.service === "PLANET" ? "planet" : pdtp.service === "" ? "empty" : "other",
            sections: pdtp.sections.map((s) => ({ type: s.type, bytes: s.body.length })),
          });
          const result = this.#pdtp.accept(pdtp, channel);
          this.#updateRtpEndpointFromSource(source);
          for (const reply of result.replies)
            await this.#sendGroupPdtp(reply, extension?.sourceChannel ?? channel);
          for (const message of result.messages) {
            if (this.#conference.accept(message)) {
              this.#emitConference();
            }
          }
          this.#debug({
            type: "group_pdtp_handled",
            replies: result.replies.length,
            messages: result.messages.length,
          });
          continue;
        }
        const decrypted = await this.#decryptMediaRtp(wire);
        const parsed = parseRtp(decrypted.rtp);
        if (this.#rtp && parsed.payloadType !== this.#rtp.payloadType) {
          this.#debug({
            type: "media_ignored",
            reason: "unexpected_payload_type",
            payloadType: parsed.payloadType,
            expectedPayloadType: this.#rtp.payloadType,
            ssrc: parsed.ssrc,
          });
          continue;
        }
        this.#updateRtpEndpointFromSource(source);
        for (const audio of this.#groupJoined ? unpackXrtp(parsed) : [parsed]) {
          const payload = audio.payload;
          if (payload.length === 0 || audio.payloadType !== this.#rtp?.payloadType) {
            this.#debug({
              type: "media_ignored",
              reason: "empty_audio_payload",
              payloadType: audio.payloadType,
              ssrc: audio.ssrc,
            });
            continue;
          }
          const frames = depacketizeEas2(payload);
          this.#debug({
            type: "media_recv",
            bytes: wire.length,
            payloadBytes: payload.length,
            payloadType: audio.payloadType,
            firstByte: payload[0],
            ssrc: audio.ssrc,
            mediaKeyMode: decrypted.mode,
            mediaKeySwitched: decrypted.switched,
            audioFrames: frames.length,
          });
          yield { ssrc: audio.ssrc, timestamp: audio.timestamp, frames };
        }
      } catch (e) {
        this.#debug({
          type: "media_decrypt_fail",
          bytes: wire.length,
          rtpPayloadType: wire.length > 1 ? wire[1] & 0x7f : undefined,
          rtpSecondByte: wire.length > 1 ? wire[1] : undefined,
          reason: e instanceof Error ? e.message : String(e),
        });
        // Drop unauthenticated media.
      }
    }
  }
}
