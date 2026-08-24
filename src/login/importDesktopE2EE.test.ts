import { describe, expect, test } from "bun:test";
import { generateKeyPair } from "curve25519-js";
import {
  derivePubKey,
  loadDesktopE2EEKeyDump,
  loadSbcBackupKeyDumps,
  mergeDesktopE2EEKeyDumps,
  normalizeDesktopE2EEKey,
  type DesktopE2EEKeyDump,
} from "./importDesktopE2EE.js";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function makePair(): { privB64: string; pubB64: string } {
  const seed = new Uint8Array(32).map((_, i) => (i * 7 + 3) % 256);
  const pair = generateKeyPair(seed);
  return {
    privB64: Buffer.from(pair.private).toString("base64"),
    pubB64: Buffer.from(pair.public).toString("base64"),
  };
}

describe("normalizeDesktopE2EEKey", () => {
  test("desktop 形式をそのまま正規化", () => {
    const { privB64, pubB64 } = makePair();
    const key = normalizeDesktopE2EEKey({
      keyId: 123,
      privKey: privB64,
      pubKey: pubB64,
      e2eeVersion: 1,
    });
    expect(key?.keyId).toBe(123);
    expect(key?.pubKey).toBe(pubB64);
  });

  test("SBC 形式を受け入れる", () => {
    const { privB64, pubB64 } = makePair();
    const key = normalizeDesktopE2EEKey({
      keyID: 456,
      e2eeKey: {
        created_time: 1700000000,
        encoded_private_key: privB64,
        encoded_public_key: pubB64,
        version: 1,
      },
    });
    expect(key?.keyId).toBe(456);
    expect(key?.pubKey).toBe(pubB64);
    expect(key?.e2eeVersion).toBe(1);
  });

  test("pubKey 欠落時は privKey から導出", () => {
    const { privB64, pubB64 } = makePair();
    const key = normalizeDesktopE2EEKey({ keyId: 789, privKey: privB64 });
    expect(key?.pubKey).toBe(pubB64);
  });

  test("不正な privKey / 欠落フィールドは null", () => {
    expect(normalizeDesktopE2EEKey(null)).toBeNull();
    expect(normalizeDesktopE2EEKey({})).toBeNull();
    expect(
      normalizeDesktopE2EEKey({ keyId: 1, privKey: Buffer.from("short").toString("base64") }),
    ).toBeNull();
  });
});

describe("loadSbcBackupKeyDumps / mergeDesktopE2EEKeyDumps", () => {
  test("sbc-keys-*.json を読んで重複マージ", () => {
    const dir = mkdtempSync(join(tmpdir(), "vyline-sbc-test-"));
    try {
      const a = makePair();
      const b = makePair();
      // 古いファイル: a のみ
      writeFileSync(
        join(dir, "sbc-keys-1000.json"),
        JSON.stringify({
          mid: "uTEST",
          savedAt: "2026-01-01T00:00:00.000Z",
          e2eeKeys: [
            {
              keyID: 1001,
              e2eeKey: { encoded_private_key: a.privB64, encoded_public_key: a.pubB64 },
            },
          ],
        }),
      );
      // 新しいファイル: a(重複) + b
      writeFileSync(
        join(dir, "sbc-keys-2000.json"),
        JSON.stringify({
          mid: "uTEST",
          savedAt: "2026-08-24T00:00:00.000Z",
          e2eeKeys: [
            {
              keyID: 1001,
              e2eeKey: { encoded_private_key: a.privB64, encoded_public_key: a.pubB64 },
            },
            {
              keyID: 1002,
              e2eeKey: { encoded_private_key: b.privB64, encoded_public_key: b.pubB64 },
            },
          ],
        }),
      );
      const dump = loadSbcBackupKeyDumps(dir);
      expect(dump?.keys.length).toBe(2);
      expect(dump?.mid).toBe("uTEST");
      // マージ: desktop 側に 1002 がある想定 → sbc からは何も増えない
      const desktopDump: DesktopE2EEKeyDump = {
        mid: "uTEST",
        keys: [{ keyId: 1002, privKey: b.privB64, pubKey: b.pubB64, e2eeVersion: 1 }],
      };
      const merged = mergeDesktopE2EEKeyDumps(desktopDump, dump!);
      expect(merged.keys.length).toBe(2);
      expect(merged.keys.map((k) => k.keyId).sort()).toEqual([1001, 1002]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("存在しないディレクトリは null", () => {
    expect(loadSbcBackupKeyDumps(join(tmpdir(), "vyline-not-exist-dir"))).toBeNull();
  });

  test("loadDesktopE2EEKeyDump が壊れたエントリをスキップして統計を返す", () => {
    const dir = mkdtempSync(join(tmpdir(), "vyline-dump-test-"));
    try {
      const { privB64, pubB64 } = makePair();
      const file = join(dir, "desktop-e2ee-keys.json");
      writeFileSync(
        file,
        JSON.stringify({
          mid: "uTEST",
          keys: [
            { keyId: 1, privKey: privB64, pubKey: pubB64 },
            { keyId: 2, privKey: "!!!!not-base64-key!!!!" },
            { keyId: 1, privKey: privB64, pubKey: pubB64 }, // 重複
          ],
        }),
      );
      const dump = loadDesktopE2EEKeyDump(file);
      expect(dump?.keys.length).toBe(1);
      expect(dump?.keys[0]?.keyId).toBe(1);
      expect(dump?.invalidCount).toBe(1);
      expect(dump?.duplicateCount).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("derivePubKey は Curve25519 公開鍵を返す", () => {
    const { privB64, pubB64 } = makePair();
    const derived = derivePubKey(Buffer.from(privB64, "base64"));
    expect(derived?.toString("base64")).toBe(pubB64);
    expect(derivePubKey(Buffer.from("bad"))).toBeNull();
  });
});
