export interface ConferenceMember {
    mid: string;
    connected: boolean;
    mediaFlags: number;
    sources: Array<{
        name: string;
        ssrc: number;
    }>;
}
/** Windows: notifier PLANET/stream1 → conf_msg_container (0x59b8e0),
 * FULL/PARTIAL update (0x5ed7c0), source-list replacement (0x5ee1a4).
 * No names, roster persistence or raw-message logging here.
 */
export declare class ConferenceState {
    #private;
    hasChannel(id: number): boolean;
    get videoSources(): Array<{
        mid: string;
        ssrc: number;
        channel: number;
    }>;
    get members(): ConferenceMember[];
    accept(container: Uint8Array): boolean;
    /** PARTICIPATE_RSP.contents carries raw conference_info, not the PDTP wrapper. */
    acceptInfo(conference: Uint8Array, compression?: number): boolean;
}
