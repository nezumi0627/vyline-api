export declare const MAX_VIDEO_FRAME_BYTES: number;
export interface EncodedVideoFrame {
    /** A complete raw VP8 frame (not IVF or RFC 7741 payloads). */
    data: Uint8Array;
    key: boolean;
    /** Unsigned 90 kHz RTP timestamp. */
    timestamp: number;
    rotation?: number;
    /** Conference-verified sender; absent for direct calls and local uploads. */
    sourceMid?: string;
}
export declare function validateVp8(data: Uint8Array, expectedKey?: boolean): void;
export declare function packetizeEvs3(data: Uint8Array, key: boolean, pictureId: number, fragmentBytes?: number): Uint8Array[];
export declare function parseEvs3(payload: Uint8Array, allowLayers?: boolean): {
    pictureId: number;
    begin: boolean;
    end: boolean;
    key: boolean;
    rotation: number;
    offset: number;
    spatialId: number;
    temporalId: number;
};
interface VideoRtpPacket {
    payload: Uint8Array;
    seq: number;
    timestamp: number;
    ssrc: number;
    marker: boolean;
}
export declare class Evs3Assembler {
    #private;
    private readonly onInvalid?;
    constructor(onInvalid?: (reason: string) => void);
    clear(): void;
    push(packet: VideoRtpPacket, now?: number): EncodedVideoFrame | undefined;
}
export {};
