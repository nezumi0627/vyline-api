import { parseRtp } from "../srtp.js";
type Rtp = ReturnType<typeof parseRtp>;
/** Native VSD element 1: per-frame signal classification plus packet level. */
export declare function buildGroupVsd(frames: readonly [{
    level: number;
    signal: 0 | 1 | 2;
}, {
    level: number;
    signal: 0 | 1 | 2;
}]): Uint8Array;
/** Common fields are not numbered elements (Windows 0xee4d0/0x1a070c).
 * 0x0240 has no channel fields, while 0x0261 carries one destination word.
 */
export declare function readPlanetRtpExtension(rtp: Rtp): {
    channel: number;
    sourceChannel?: number;
    elements: Uint8Array;
} | undefined;
/** Already authenticated outer RTP only; inner packets are plaintext, not SRTP.
 * Windows ampkit 1.0.0.911: demux 0x209ba0, PLD decode 0xefbd0,
 * extension scan 0xecb40. Lengths use QUIC-style big-endian, NOT protobuf.
 */
export declare function unpackXrtp(outer: Rtp): Rtp[];
export {};
