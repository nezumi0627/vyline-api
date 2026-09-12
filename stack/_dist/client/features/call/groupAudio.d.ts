import type { CodecFactory, PcmFrame } from "./audio.ts";
export interface CallAudioPacket {
    ssrc: number;
    timestamp: number;
    frames: Uint8Array[];
}
/** Bounded 48kHz mono playout, 60ms initial jitter cushion, 30 sources max.
 * ponytail: late/reordered encoded packets are dropped, not re-decoded;
 * add an encoded jitter buffer/PLC if measured network loss warrants it.
 */
export declare class GroupAudioMixer {
    #private;
    private readonly codecs;
    constructor(codecs: CodecFactory);
    push(packet: CallAudioPacket, now: number): void;
    read(now: number): PcmFrame | undefined;
    remove(ssrc: number): void;
    close(): void;
}
