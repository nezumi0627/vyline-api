/**
 * PLANET normal-audio (pmap=1) is EAS2, not raw Opus.
 * LINE 26.13 ARM64: vns_audio_pyld_hdr_parse 0x7f62a4,
 * eas2_depacketizer_depack 0x805060; single-frame TX 0x805cf4..0x805fe4.
 * The outer byte is chunk-id << 4 | silence << 3. EAS2 replaces the
 * Opus frame-count bits with speech/config flags; never decode it as Opus.
 */
export declare function packetizeEas2(opus: Uint8Array): Uint8Array;
/** Aggregate up to six of our 20ms Opus frames (native ptime 20..120ms). */
export declare function packetizeEas2Frames(frames: readonly Uint8Array[]): Uint8Array;
export declare function depacketizeEas2(payload: Uint8Array): Uint8Array[];
