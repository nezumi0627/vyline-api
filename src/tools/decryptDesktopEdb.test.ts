import { expect, test } from "bun:test";
import { createCipheriv } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deriveWxSqlite3BaseKey128, pageIv, pageKey128 } from "../desktop/wxSqlite3.js";
import { decryptDesktopEdbSnapshot } from "./decryptDesktopEdb.js";

const toolPath = join(import.meta.dir, "decryptDesktopEdb.ts");
const absentEdb = join(import.meta.dir, "does-not-exist.edb");
const passphrase = Buffer.from("0123456789abcdef0123456789abcdef", "ascii");
const sqliteHeader = Buffer.from("SQLite format 3\0", "ascii");

test("requires explicit consent before decrypting a Desktop snapshot in memory", () => {
  expect(() => decryptDesktopEdbSnapshot(absentEdb, 0, false)).toThrow(
    "Explicit consent is required",
  );
});

function makeEncryptedFixture(): Buffer {
  const baseKey = deriveWxSqlite3BaseKey128(passphrase);
  const page = Buffer.alloc(1024);
  sqliteHeader.copy(page);
  page.writeUInt16BE(1024, 16);
  page[18] = 1;
  page[19] = 1;
  page[21] = 64;
  page[22] = 32;
  page[23] = 32;
  page[100] = 0x0d;
  const cipher = createCipheriv("aes-128-cbc", pageKey128(baseKey, 1), pageIv(1));
  cipher.setAutoPadding(false);
  const encryptedHeader = Buffer.concat([cipher.update(page.subarray(0, 16)), cipher.final()]);
  const bodyCipher = createCipheriv("aes-128-cbc", pageKey128(baseKey, 1), pageIv(1));
  bodyCipher.setAutoPadding(false);
  const encryptedBody = Buffer.concat([bodyCipher.update(page.subarray(16)), bodyCipher.final()]);
  const encrypted = Buffer.concat([encryptedHeader, encryptedBody]);
  encrypted.copy(encrypted, 8, 16, 24);
  page.subarray(16, 24).copy(encrypted, 16);
  return encrypted;
}

test("requires explicit consent before a live process memory scan", () => {
  const result = spawnSync(process.execPath, [toolPath, "--edb", absentEdb], {
    encoding: "utf8",
    timeout: 10_000,
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  expect(result.status).not.toBe(0);
  expect(output).toContain("メモリ走査の利用条件");
  expect(output).toContain("--accept-risk");
  expect(output).not.toContain("No .edb found");
});

test("shows the terms and records no secret when consent is supplied", () => {
  const result = spawnSync(process.execPath, [toolPath, "--edb", absentEdb, "--accept-risk"], {
    encoding: "utf8",
    timeout: 10_000,
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  expect(result.status).not.toBe(0);
  expect(output).toContain("メモリ走査の利用条件");
  expect(output).toContain("自己責任");
  expect(output).toContain("No .edb found");
  expect(output).not.toContain("passphrase-candidates.json");
});

test("keeps explicit passphrase mode independent from process-memory consent", () => {
  const result = spawnSync(
    process.execPath,
    [toolPath, "--edb", absentEdb, "--passphrase", "0123456789abcdef0123456789abcdef"],
    { encoding: "utf8", timeout: 10_000 },
  );
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  expect(result.status).not.toBe(0);
  expect(output).not.toContain("メモリ走査の利用条件");
  expect(output).toContain("No .edb found");
});

test("never writes or prints candidate passphrases when verification fails", () => {
  const dir = mkdtempSync(join(tmpdir(), "vyline-edb-consent-test-"));
  const dbPath = join(dir, "fixture.edb");
  const outDir = join(dir, "out");
  const passphrase = "deadbeef0123456789abcdef01234567";
  const file = Buffer.alloc(1024);
  file.writeUInt16BE(1024, 16);
  file[18] = 1;
  file[19] = 1;
  file[21] = 64;
  file[22] = 32;
  file[23] = 32;
  writeFileSync(dbPath, file);

  try {
    const result = spawnSync(
      process.execPath,
      [toolPath, "--edb", dbPath, "--out-dir", outDir, "--passphrase", passphrase],
      { encoding: "utf8", timeout: 10_000 },
    );
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    const artifacts = existsSync(outDir) ? readFiles(outDir) : [];

    expect(result.status).not.toBe(0);
    expect(output).not.toContain(passphrase);
    expect(artifacts.some((content) => content.includes(passphrase))).toBe(false);
    expect(artifacts.some((content) => content.includes("passphrase-candidates"))).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("decrypts a valid fixture and refuses to overwrite the requested output", () => {
  const dir = mkdtempSync(join(tmpdir(), "vyline-edb-output-test-"));
  const dbPath = join(dir, "fixture.edb");
  const outPath = join(dir, "fixture.sqlite");
  writeFileSync(dbPath, makeEncryptedFixture());

  try {
    const args = [
      toolPath,
      "--edb",
      dbPath,
      "--out",
      outPath,
      "--passphrase",
      passphrase.toString(),
    ];
    const first = spawnSync(process.execPath, args, { encoding: "utf8", timeout: 10_000 });
    expect(first.status).toBe(0);
    const decrypted = readFileSync(outPath);
    expect(decrypted.subarray(0, 16)).toEqual(sqliteHeader);
    expect(decrypted[100]).toBe(0x0d);

    const second = spawnSync(process.execPath, args, { encoding: "utf8", timeout: 10_000 });
    expect(second.status).not.toBe(0);
    expect(`${second.stdout ?? ""}${second.stderr ?? ""}`).toContain("出力先が既に存在します");
    expect(readFileSync(outPath)).toEqual(decrypted);
    expect(readdirSync(dir)).not.toContain("decrypt-meta.json");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("memory scanning accepts only the consented local LINE process and does not write keys", () => {
  if (process.platform !== "win32") return;
  const dir = mkdtempSync(join(tmpdir(), "vyline-edb-memory-scan-test-"));
  const dbPath = join(dir, "fixture.edb");
  const file = Buffer.alloc(1024);
  file.writeUInt16BE(1024, 16);
  file[18] = 1;
  file[19] = 1;
  file[21] = 64;
  file[22] = 32;
  file[23] = 32;
  writeFileSync(dbPath, file);

  try {
    const result = spawnSync(
      process.execPath,
      [toolPath, "--edb", dbPath, "--out-dir", join(dir, "out"), "--pid", "4", "--accept-risk"],
      { encoding: "utf8", timeout: 130_000 },
    );
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    expect(result.status).not.toBe(0);
    expect(output).toContain("指定PIDはLINE Desktopではありません");
    expect(output).not.toMatch(/[0-9a-f]{32}/i);
    expect(readdirSync(dir)).not.toContain("passphrase-candidates.json");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function readFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((name) => statSync(join(dir, name)).isFile())
    .map((name) => readFileSync(join(dir, name), "utf8"));
}
