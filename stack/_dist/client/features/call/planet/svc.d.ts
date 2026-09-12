/** Single spatial/temporal VP8 layer, with one VFD record per RTP packet. */
export declare function packetizeSvcVp8(data: Uint8Array, key: boolean, pictureId: number, sequence: number, resolution: 0 | 1 | 2 | 3, fragmentBytes?: number, codec?: 3 | 4): Array<{
    payload: Uint8Array;
    extensionData: Uint8Array;
}>;
/** Validate the SVC profile, then reuse the bounded normal-video assembler. */
export declare function unwrapSvcVp8(payload: Uint8Array): Uint8Array;
/** VFD version 1, exactly one base-layer VP8 packet descriptor. */
export declare function parseSvcVfd(elements: Uint8Array, payload: Uint8Array, allowMissing?: boolean): number | undefined;
