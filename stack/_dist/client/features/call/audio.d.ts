export interface PcmFrame {
    samples: Int16Array;
    sampleRate: number;
    channels: number;
    timestamp?: number;
}
/** Per-frame AC energy in -dBov units (RFC 6464); DC is not audio activity. */
export declare function pcmAudioLevel(samples: Int16Array): number;
/** Activity includes music, not just human speech (native VSD VOICED=2).
 * ponytail: OpusScript lacks native analysis getters; use a -60dBov energy
 * gate with 200ms quiet-tail hold. Replace with codec VAD if noise is forwarded.
 */
export declare class AudioActivityDetector {
    #private;
    signal(level: number, now?: number): 0 | 1 | 2;
}
export interface AudioSource {
    frames(opts?: {
        signal?: AbortSignal;
    }): AsyncIterable<PcmFrame>;
    close?(): Promise<void> | void;
}
export interface AudioSink {
    write(frame: PcmFrame): Promise<void> | void;
    end?(): Promise<void> | void;
}
export interface NativeGroupOpusPacketizeOptions {
    /**
     * Number of bytes before the raw Opus TOC byte in each input packet.
     * Legacy helper input is shaped as `prefix + raw Opus`, not received EAS2.
     */
    inputPrefixBytes?: number;
}
export declare function streamSource(stream: ReadableStream<PcmFrame>): AudioSource;
export declare function bufferSource(opts: {
    samples: Int16Array;
    sampleRate: number;
    channels?: number;
    frameDurationMs?: number;
}): AudioSource;
export interface FileDecoder {
    (bytes: Uint8Array): Promise<{
        samples: Int16Array;
        sampleRate: number;
        channels: number;
    }>;
}
export declare function fileSource(opts: {
    bytes: Uint8Array;
    decode: FileDecoder;
    frameDurationMs?: number;
}): Promise<AudioSource>;
export declare function bufferSink(): AudioSink & {
    frames: PcmFrame[];
};
export declare function streamSink(stream: WritableStream<PcmFrame>): AudioSink;
export declare function packetizeNativeGroupOpusPairs(packets: Uint8Array[], opts?: NativeGroupOpusPacketizeOptions): Uint8Array[];
export interface AudioEncoder {
    encode(frame: PcmFrame): Uint8Array | null;
    close?(): void;
}
export interface AudioDecoder {
    decode(packet: Uint8Array): PcmFrame | null;
    close?(): void;
}
export interface CodecFactory {
    newEncoder(opts: {
        sampleRate: number;
        channels: number;
        bitrate?: number;
        frameDurationMs?: number;
        bandwidth?: "narrowband" | "mediumband" | "wideband" | "superwideband" | "fullband";
        signal?: "auto" | "voice" | "music";
        vbr?: boolean;
    }): AudioEncoder;
    newDecoder(opts: {
        sampleRate: number;
        channels: number;
    }): AudioDecoder;
}
export declare const defaultCodecFactory: CodecFactory;
/** Minimal 16-bit PCM WAV decoder. Throws on compressed formats. */
export declare function decodeWavSync(bytes: Uint8Array): {
    samples: Int16Array;
    sampleRate: number;
    channels: number;
};
/** Linear-interpolated resample of interleaved 16-bit PCM. */
export declare function resampleLinear(samples: Int16Array, fromRate: number, toRate: number, channels: number): Int16Array;
