import { existsSync } from "node:fs";
import { mkdtemp, open, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { E2EE } from "../e2ee/mod.ts";
import { decryptE2eeMediaResponseToFile, encryptE2eeMediaFile, LineObs } from "./mod.ts";

const roots: string[] = [];
const keys = {
  encKey: Buffer.alloc(32, 0x11),
  macKey: Buffer.alloc(32, 0x22),
  nonce: Buffer.alloc(16, 0x33),
};

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "vyline-e2ee-file-"));
  roots.push(root);
  return root;
}

async function expectOnlyFiles(root: string, names: string[]): Promise<void> {
  expect((await readdir(root)).sort()).toEqual([...names].sort());
}

function makeFileObs(options?: {
  encryptMessage?: () => Promise<Buffer[]>;
  sendMessage?: (args: Record<string, unknown>) => Promise<Record<string, unknown>>;
}) {
  const e2ee = new E2EE({} as never);
  const uploaded: Array<{ bytes: Buffer; obsPath: string }> = [];
  const sent: Record<string, unknown>[] = [];
  let deriveCalls = 0;
  const client = {
    e2ee: {
      deriveKeyMaterial(keyMaterial: Buffer) {
        deriveCalls += 1;
        return e2ee.deriveKeyMaterial(keyMaterial);
      },
      encryptE2EEMessage:
        options?.encryptMessage ?? (() => Promise.resolve([Buffer.from("encrypted-envelope")])),
      decryptE2EEDataMessage() {
        throw new Error("the plaintext keyMaterial fast path should not decrypt chunks");
      },
    },
    talk: {
      async sendMessage(args: Record<string, unknown>) {
        sent.push(args);
        if (options?.sendMessage) return await options.sendMessage(args);
        return { ...args, id: "message-1" };
      },
    },
    request: {
      getHeader() {
        return {};
      },
    },
    log() {},
  };
  const obs = new LineObs(client as never);
  obs.uploadObjectForService = (async (upload: { data: Blob; obsPath?: string }) => {
    uploaded.push({
      bytes: Buffer.from(await upload.data.arrayBuffer()),
      obsPath: upload.obsPath ?? "",
    });
    return { objId: "OBJ-1", objHash: "HASH-1", headers: new Headers() };
  }) as never;
  return { e2ee, obs, sent, uploaded, deriveCalls: () => deriveCalls };
}

describe("file-backed E2EE media", () => {
  test("round-trips a large sparse file with bounded RSS", async () => {
    const root = await tempRoot();
    const sourcePath = join(root, "source.bin");
    const encryptedPath = join(root, "encrypted.bin");
    const restoredPath = join(root, "restored.bin");
    const source = await open(sourcePath, "wx+");
    const requestedSize = Number(process.env.VYLINE_E2EE_FILE_TEST_BYTES ?? 64 * 1024 * 1024);
    const size = Number.isSafeInteger(requestedSize)
      ? Math.min(500 * 1024 * 1024, Math.max(1024, requestedSize))
      : 64 * 1024 * 1024;
    try {
      await source.truncate(size);
      await source.write(Uint8Array.from([1, 2, 3, 4]), 0, 4, 0);
      await source.write(Uint8Array.from([5, 6, 7, 8]), 0, 4, size - 4);
    } finally {
      await source.close();
    }

    Bun.gc(true);
    const rssBefore = process.memoryUsage().rss;
    let peakRss = rssBefore;
    const sampler = setInterval(() => {
      peakRss = Math.max(peakRss, process.memoryUsage().rss);
    }, 5);
    try {
      const encrypted = await encryptE2eeMediaFile(sourcePath, encryptedPath, keys, size);
      expect(encrypted.size).toBe(size + 32);
      const restored = await decryptE2eeMediaResponseToFile(
        new Response(Bun.file(encryptedPath)),
        restoredPath,
        keys,
        size,
      );
      expect(restored.size).toBe(size);
    } finally {
      clearInterval(sampler);
    }

    expect((await stat(restoredPath)).size).toBe(size);
    const restored = await open(restoredPath, "r");
    try {
      const first = Buffer.alloc(4);
      const last = Buffer.alloc(4);
      await restored.read(first, 0, first.length, 0);
      await restored.read(last, 0, last.length, size - last.length);
      expect([...first]).toEqual([1, 2, 3, 4]);
      expect([...last]).toEqual([5, 6, 7, 8]);
    } finally {
      await restored.close();
    }
    const rssGrowth = Math.max(0, peakRss - rssBefore);
    console.info("[e2ee-file-large]", { size, rssGrowth });
    expect(rssGrowth).toBeLessThan(128 * 1024 * 1024);
  }, 180_000);

  test("rejects a modified HMAC and removes unpublished plaintext", async () => {
    const root = await tempRoot();
    const sourcePath = join(root, "source.bin");
    const encryptedPath = join(root, "encrypted.bin");
    const restoredPath = join(root, "restored.bin");
    await writeFile(sourcePath, "authenticated media");
    await encryptE2eeMediaFile(sourcePath, encryptedPath, keys, 1024);
    const encrypted = await open(encryptedPath, "r+");
    try {
      const info = await encrypted.stat();
      const last = Buffer.alloc(1);
      await encrypted.read(last, 0, 1, info.size - 1);
      last[0] = (last[0] ?? 0) ^ 0xff;
      await encrypted.write(last, 0, 1, info.size - 1);
    } finally {
      await encrypted.close();
    }

    await expect(
      decryptE2eeMediaResponseToFile(
        new Response(Bun.file(encryptedPath)),
        restoredPath,
        keys,
        1024,
      ),
    ).rejects.toThrow("authentication failed");
    expect(existsSync(restoredPath)).toBe(false);
    expect(await readFile(sourcePath, "utf8")).toBe("authenticated media");
  });

  test("the bounded and compatibility decryptors both authenticate the HMAC", async () => {
    const e2ee = new E2EE({} as never);
    const source = Buffer.from("verified in-memory compatibility payload");
    const encrypted = await e2ee.encryptByKeyMaterial(source);
    expect(await e2ee.decryptByKeyMaterial(encrypted.encryptedData, encrypted.keyMaterial)).toEqual(
      source,
    );
    const tampered = Buffer.from(encrypted.encryptedData);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
    await expect(e2ee.decryptByKeyMaterial(tampered, encrypted.keyMaterial)).rejects.toThrow(
      "authentication failed",
    );
  });

  test("matches the compatibility encryptor at AES and stream chunk boundaries", async () => {
    const root = await tempRoot();
    const e2ee = new E2EE({} as never);
    const keyMaterial = Buffer.alloc(32, 0x47);
    const derived = await e2ee.deriveKeyMaterial(keyMaterial);

    for (const size of [1, 15, 16, 17, 65_535, 65_536, 65_537]) {
      const sourcePath = join(root, `source-${size}.bin`);
      const encryptedPath = join(root, `encrypted-${size}.bin`);
      const source = Buffer.alloc(size);
      for (let index = 0; index < source.length; index++) {
        source[index] = (index * 31 + size) & 0xff;
      }
      await writeFile(sourcePath, source);

      await encryptE2eeMediaFile(sourcePath, encryptedPath, derived, size);
      const compatibility = await e2ee.encryptByKeyMaterial(source, keyMaterial);
      expect(await readFile(encryptedPath)).toEqual(compatibility.encryptedData);
    }
  });

  test("does not encrypt or upload when the peer requests the plain media flow", async () => {
    const root = await tempRoot();
    const sourcePath = join(root, "source.bin");
    await writeFile(sourcePath, "plain-flow-source");
    const fixture = makeFileObs({
      encryptMessage: () => Promise.reject(new Error("E2EE_RETRY_PLAIN")),
    });

    await expect(
      fixture.obs.uploadMediaByE2EEFromFile({
        dataPath: sourcePath,
        size: (await stat(sourcePath)).size,
        mimeType: "application/octet-stream",
        oType: "file",
        to: "u-recipient",
        filename: "source.bin",
      }),
    ).rejects.toThrow("E2EE_RETRY_PLAIN");

    expect(fixture.uploaded).toHaveLength(0);
    expect(fixture.sent).toHaveLength(0);
    expect(fixture.deriveCalls()).toBe(0);
    await expectOnlyFiles(root, ["source.bin"]);
  });

  test("uploads a compatible encrypted file, sends its metadata, and removes temporary files", async () => {
    const root = await tempRoot();
    const sourcePath = join(root, "report.pdf");
    const source = Buffer.from("file-backed OBS upload payload");
    await writeFile(sourcePath, source);
    const fixture = makeFileObs();

    const message = await fixture.obs.uploadMediaByE2EEFromFile({
      dataPath: sourcePath,
      size: source.byteLength,
      mimeType: "application/pdf",
      oType: "file",
      to: "u-recipient",
      filename: "report.pdf",
    });

    expect(message.id).toBe("message-1");
    expect(fixture.uploaded).toHaveLength(1);
    expect(fixture.uploaded[0]?.obsPath).toContain("talk/emf/reqid-");
    expect(fixture.uploaded[0]?.bytes.byteLength).toBe(source.byteLength + 32);
    expect(fixture.sent).toHaveLength(1);
    const sent = fixture.sent[0]!;
    expect(sent.contentType).toBe(14);
    expect(sent.e2ee).toBe(true);
    expect(sent.chunks).toEqual([Buffer.from("encrypted-envelope")]);
    expect(sent.contentMetadata).toMatchObject({
      SID: "emf",
      OID: "OBJ-1",
      FILE_SIZE: String(source.byteLength + 32),
      fileName: "report.pdf",
      e2eeVersion: "2",
    });
    const metadata = sent.contentMetadata as Record<string, string>;
    expect(
      await fixture.e2ee.decryptByKeyMaterial(fixture.uploaded[0]!.bytes, metadata.keyMaterial!),
    ).toEqual(source);
    expect(await readFile(sourcePath)).toEqual(source);
    await expectOnlyFiles(root, ["report.pdf"]);
  });

  test("removes encrypted temporary files when OBS upload fails", async () => {
    const root = await tempRoot();
    const sourcePath = join(root, "source.bin");
    await writeFile(sourcePath, "upload failure source");
    const fixture = makeFileObs();
    fixture.obs.uploadObjectForService = (() =>
      Promise.reject(new Error("OBS unavailable"))) as never;

    await expect(
      fixture.obs.uploadMediaByE2EEFromFile({
        dataPath: sourcePath,
        size: (await stat(sourcePath)).size,
        mimeType: "application/octet-stream",
        oType: "file",
        to: "u-recipient",
      }),
    ).rejects.toThrow("OBS unavailable");

    expect(fixture.sent).toHaveLength(0);
    await expectOnlyFiles(root, ["source.bin"]);
  });

  test("stops a pre-aborted upload before key or OBS work and leaves no temporary file", async () => {
    const root = await tempRoot();
    const sourcePath = join(root, "source.bin");
    await writeFile(sourcePath, "aborted upload source");
    const fixture = makeFileObs();
    const controller = new AbortController();
    controller.abort();

    await expect(
      fixture.obs.uploadMediaByE2EEFromFile({
        dataPath: sourcePath,
        size: (await stat(sourcePath)).size,
        mimeType: "application/octet-stream",
        oType: "file",
        to: "u-recipient",
        signal: controller.signal,
      }),
    ).rejects.toThrow();

    expect(fixture.uploaded).toHaveLength(0);
    expect(fixture.sent).toHaveLength(0);
    expect(fixture.deriveCalls()).toBe(0);
    await expectOnlyFiles(root, ["source.bin"]);
  });

  test("removes encrypted temporary files when message publication fails", async () => {
    const root = await tempRoot();
    const sourcePath = join(root, "source.bin");
    await writeFile(sourcePath, "send failure source");
    const fixture = makeFileObs({
      sendMessage: () => Promise.reject(new Error("Talk send failed")),
    });

    await expect(
      fixture.obs.uploadMediaByE2EEFromFile({
        dataPath: sourcePath,
        size: (await stat(sourcePath)).size,
        mimeType: "application/octet-stream",
        oType: "file",
        to: "u-recipient",
      }),
    ).rejects.toThrow("Talk send failed");

    expect(fixture.uploaded).toHaveLength(1);
    expect(fixture.sent).toHaveLength(1);
    await expectOnlyFiles(root, ["source.bin"]);
  });

  test("downloads and authenticates the plaintext keyMaterial fast path to a file", async () => {
    const root = await tempRoot();
    const targetPath = join(root, "downloaded.bin");
    const source = Buffer.from("authenticated OBS response");
    const keyMaterial = Buffer.alloc(32, 0x5a);
    const e2ee = new E2EE({} as never);
    const encrypted = await e2ee.encryptByKeyMaterial(source, keyMaterial);
    const fixture = makeFileObs();
    const requests: Array<{ oid: string; obsPath: string }> = [];
    fixture.obs.downloadObjectResponseForService = (async (request: {
      oid: string;
      obsPath: string;
    }) => {
      requests.push(request);
      return new Response(encrypted.encryptedData, {
        headers: { "content-type": "application/octet-stream" },
      });
    }) as never;

    const result = await fixture.obs.downloadMediaByE2EEToFile(
      {
        id: "123456",
        to: "u-recipient",
        contentMetadata: {
          OID: "OBJ-2",
          SID: "emi",
          keyMaterial: keyMaterial.toString("base64"),
          fileName: "photo.jpg",
        },
      } as never,
      targetPath,
      1024,
    );

    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ oid: "OBJ-2", obsPath: "talk/emi" });
    expect(result).toMatchObject({
      path: targetPath,
      size: source.byteLength,
      fileName: "photo.jpg",
      contentType: "application/octet-stream",
    });
    expect(await readFile(targetPath)).toEqual(source);
  });

  test("rejects invalid download metadata before opening the OBS response", async () => {
    const root = await tempRoot();
    const fixture = makeFileObs();
    let downloads = 0;
    fixture.obs.downloadObjectResponseForService = (() => {
      downloads += 1;
      return Promise.resolve(new Response("should not be read"));
    }) as never;

    await expect(
      fixture.obs.downloadMediaByE2EEToFile(
        {
          id: "123456",
          to: "u-recipient",
          contentMetadata: {
            OID: "OBJ-2",
            SID: "emi",
            keyMaterial: Buffer.alloc(31).toString("base64"),
          },
        } as never,
        join(root, "invalid-key.bin"),
        1024,
      ),
    ).rejects.toThrow("exactly 32 bytes");

    await expect(
      fixture.obs.downloadMediaByE2EEToFile(
        {
          id: "123456",
          to: "u-recipient",
          contentMetadata: {
            SID: "emi",
            keyMaterial: Buffer.alloc(32).toString("base64"),
          },
        } as never,
        join(root, "missing-oid.bin"),
        1024,
      ),
    ).rejects.toThrow("object metadata is missing");

    expect(downloads).toBe(0);
    await expectOnlyFiles(root, []);
  });

  test("preserves an existing target and cancels the response when setup fails", async () => {
    const root = await tempRoot();
    const targetPath = join(root, "existing.bin");
    await writeFile(targetPath, "keep-existing-data");
    let cancelled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(64));
      },
      cancel() {
        cancelled += 1;
      },
    });

    await expect(
      decryptE2eeMediaResponseToFile(new Response(body), targetPath, keys, 1024),
    ).rejects.toThrow();
    expect(cancelled).toBe(1);
    expect(await readFile(targetPath, "utf8")).toBe("keep-existing-data");
  });
});
