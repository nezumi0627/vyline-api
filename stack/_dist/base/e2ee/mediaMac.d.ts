export type MediaMacType = "file" | "video";
/** LINE Encryption Overview v2.2: video authenticates SHA-256 hashes of 128 KiB chunks. */
export declare function createMediaMac(key: Uint8Array, type?: MediaMacType): {
    update(bytes: Uint8Array): void;
    digest(): Buffer;
};
