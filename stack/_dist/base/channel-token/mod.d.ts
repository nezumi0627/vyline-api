import type { BaseClient } from "../core/mod.ts";
export type ChannelTokenIssuance = "issue" | "approve-and-issue";
/** Per-account channel-token lifecycle backed by the client's account storage. */
export declare class ChannelTokenManager {
    #private;
    readonly client: BaseClient;
    constructor(client: BaseClient);
    get(channelId: string, options?: {
        force?: boolean;
        approve?: boolean;
    }): Promise<string>;
    invalidate(channelId: string): Promise<void>;
    reissue(channelId: string, approve?: boolean): Promise<string>;
}
