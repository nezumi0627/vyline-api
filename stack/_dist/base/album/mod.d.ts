import type { BaseClient } from "../mod.ts";
import type { LooseType } from "@vyline/loose-types";
export type AlbumResponse<T = LooseType> = {
    code: number;
    message?: string;
    result: T | null;
};
export declare class Album {
    private readonly client;
    private token?;
    constructor(client: BaseClient);
    call<T = LooseType>(options: {
        path: string;
        method?: "GET" | "POST" | "PUT" | "DELETE";
        query?: Record<string, string | number | undefined>;
        body?: LooseType;
    }): Promise<AlbumResponse<T>>;
}
