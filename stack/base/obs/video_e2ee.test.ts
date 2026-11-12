import crypto from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { E2EE } from "../e2ee/mod.ts";
import { encryptE2eeMediaFile, LineObs } from "./mod.ts";

const keyMaterial = Buffer.alloc(32, 0x5a);
const derived = Buffer.from(crypto.hkdfSync("sha256", keyMaterial, Buffer.alloc(0), "FileEncryption", 76));
const keys = {
  encKey: derived.subarray(0, 32),
  macKey: derived.subarray(32, 64),
  nonce: Buffer.concat([derived.subarray(64, 76), Buffer.alloc(4)]),
};
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

// Independent fixture based on LINE Encryption Overview v2.2, section Video
// Encryption. Do not use the implementation's encryptor to generate test input.
function officialVideo(plain: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-ctr", keys.encKey, keys.nonce);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const hashes: Buffer[] = [];
  for (let i = 0; i < ciphertext.length; i += 131072) {
    hashes.push(crypto.createHash("sha256").update(ciphertext.subarray(i, i + 131072)).digest());
  }
  const tag = crypto.createHmac("sha256", keys.macKey).update(Buffer.concat(hashes)).digest();
  return Buffer.concat([ciphertext, tag]);
}

function makeObs(data: Buffer) {
  const e2ee = new E2EE({} as never);
  const obs = new LineObs({ e2ee } as never);
  obs.downloadObjectForService = async () => new Blob([new Uint8Array(data)], { type: "video/mp4" });
  obs.downloadObjectResponseForService = async () => {
    let offset = 0;
    return new Response(new ReadableStream({
      pull(controller) {
        if (offset >= data.length) return controller.close();
        // Deliberately split both video chunks and the trailing MAC across reads.
        const end = Math.min(offset + 16381, data.length);
        controller.enqueue(new Uint8Array(data.subarray(offset, end)));
        offset = end;
      },
    }), { headers: { "content-type": "video/mp4", "content-length": String(data.length) } });
  };
  return { e2ee, obs };
}

const message = {
  id: "123456",
  to: `u${"1".repeat(32)}`,
  contentType: 2,
  contentMetadata: { SID: "emv", OID: "video-fixture", keyMaterial: keyMaterial.toString("base64") },
};

for (const size of [1024, 131072, 131073, 262161]) {
  test(`official video MAC decrypts through OBS at ${size} bytes`, async () => {
    const plain = Buffer.alloc(size, 0x37);
    const { obs } = makeObs(officialVideo(plain));
    const file = await obs.downloadMediaByE2EE(message as never);
    expect(Buffer.from(await file!.arrayBuffer())).toEqual(plain);
    expect(file!.type).toBe("video/mp4");

    const root = await mkdtemp(join(tmpdir(), "vyline-video-"));
    roots.push(root);
    const path = join(root, "verified.mp4");
    await obs.downloadMediaByE2EEToFile(message as never, path, plain.length);
    expect(await readFile(path)).toEqual(plain);
  });
}

test("video ciphertext and tags are verified before accepting the media", async () => {
  const plain = Buffer.alloc(262161, 0x37);
  for (const index of [0, 131072, plain.length, plain.length + 31]) {
    const data = officialVideo(plain);
    data[index] = data[index]! ^ 1;
    const { obs } = makeObs(data);
    await expect(obs.downloadMediaByE2EE(message as never)).rejects.toThrow("authentication failed");
    const root = await mkdtemp(join(tmpdir(), "vyline-video-"));
    roots.push(root);
    const path = join(root, "rejected.mp4");
    await expect(obs.downloadMediaByE2EEToFile(message as never, path, plain.length))
      .rejects.toThrow("authentication failed");
    expect(await Bun.file(path).exists()).toBe(false);
  }
});

test("legacy Vyline video still requires a valid file MAC", async () => {
  const e2ee = new E2EE({} as never);
  const plain = Buffer.from("legacy authenticated video");
  const legacy = await e2ee.encryptByKeyMaterial(plain, keyMaterial);
  const { obs } = makeObs(legacy.encryptedData);
  expect(Buffer.from(await (await obs.downloadMediaByE2EE(message as never))!.arrayBuffer()))
    .toEqual(plain);
  await expect(e2ee.decryptByKeyMaterial(officialVideo(plain), keyMaterial))
    .rejects.toThrow("authentication failed");
});

test("new video encryptors match the independent official fixture", async () => {
  const e2ee = new E2EE({} as never);
  const plain = Buffer.alloc(262161, 0x37);
  const expected = officialVideo(plain);
  expect((await e2ee.encryptByKeyMaterial(plain, keyMaterial, "video")).encryptedData)
    .toEqual(expected);
  const root = await mkdtemp(join(tmpdir(), "vyline-video-"));
  roots.push(root);
  const source = join(root, "source.mp4");
  const target = join(root, "encrypted.bin");
  await writeFile(source, plain);
  await encryptE2eeMediaFile(source, target, keys, plain.length, undefined, "video");
  expect(await readFile(target)).toEqual(expected);
});
