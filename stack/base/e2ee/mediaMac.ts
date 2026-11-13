import crypto from "node:crypto";

export type MediaMacType = "file" | "video";
const VIDEO_CHUNK_BYTES = 128 * 1024;

/** LINE Encryption Overview v2.2: video authenticates SHA-256 hashes of 128 KiB chunks. */
export function createMediaMac(key: Uint8Array, type: MediaMacType = "file") {
  const hmac = crypto.createHmac("sha256", key);
  let hash = crypto.createHash("sha256");
  let chunkBytes = 0;
  return {
    update(bytes: Uint8Array): void {
      if (type === "file") {
        hmac.update(bytes);
        return;
      }
      for (let offset = 0; offset < bytes.byteLength;) {
        const length = Math.min(VIDEO_CHUNK_BYTES - chunkBytes, bytes.byteLength - offset);
        hash.update(bytes.subarray(offset, offset + length));
        offset += length;
        chunkBytes += length;
        if (chunkBytes === VIDEO_CHUNK_BYTES) {
          hmac.update(hash.digest());
          hash = crypto.createHash("sha256");
          chunkBytes = 0;
        }
      }
    },
    digest(): Buffer {
      if (type === "video" && chunkBytes > 0) hmac.update(hash.digest());
      return hmac.digest();
    },
  };
}
