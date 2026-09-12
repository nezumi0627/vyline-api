/** Native PDTP v62/section framing (Windows ampkit 0x1a04a0/0x1a2b50).
 * Only authenticated RTP payloads enter here; no raw packet logging.
 */
export declare class PdtpReader {
    readonly data: Uint8Array;
    offset: number;
    constructor(data: Uint8Array);
    get remaining(): number;
    bytes(length: number): Uint8Array;
    byte(): number;
    uint(): bigint;
    size(max?: number): number;
    string(max?: number): string;
    end(): void;
}
export declare function pdtpUint(value: bigint): Uint8Array;
export interface PdtpPacket {
    number: bigint;
    service: string;
    sections: Array<{
        type: number;
        body: Uint8Array;
    }>;
}
export declare function parsePdtp(payload: Uint8Array, sequence: number): PdtpPacket;
type PdtpReply = Omit<PdtpPacket, "number">;
export declare function buildPdtp(packet: PdtpPacket): Uint8Array;
/** Receive-side reliable notifier; ACKs refer to actual packets, never captures. */
export declare class PdtpReceiver {
    #private;
    accept(packet: PdtpPacket, channel: number): {
        replies: PdtpReply[];
        messages: Uint8Array[];
    };
}
export {};
