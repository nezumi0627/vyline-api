import { createCipheriv } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  applyWxSqlite3WalWithBaseKey,
  decryptWxSqlite3File,
  decryptWxSqlite3FileWithBaseKey,
  deriveWxSqlite3BaseKey128,
  pageIv,
  pageKey128,
  verifyWxSqlite3Passphrase,
  verifyWxSqlite3BaseKey,
} from "./wxSqlite3.js";

const PAGE_SIZE = 1024;
const PASSPHRASE = Buffer.from("0123456789abcdef0123456789abcdef", "ascii");
const SQLITE_HEADER = Buffer.from("SQLite format 3\0", "ascii");

function encryptCbc(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function makeEncryptedDatabase(pageMarker = 0): Buffer {
  const baseKey = deriveWxSqlite3BaseKey128(PASSPHRASE);
  const page = Buffer.alloc(PAGE_SIZE);
  SQLITE_HEADER.copy(page);
  page.writeUInt16BE(PAGE_SIZE, 16);
  page[18] = 1; // file format write version
  page[19] = 1; // file format read version
  page[20] = 0; // reserved bytes
  page[21] = 64;
  page[22] = 32;
  page[23] = 32;
  page[100] = 0x0d; // leaf table b-tree page
  page[200] = pageMarker;
  page.writeUInt16BE(0, 101); // no cells
  page.writeUInt16BE(PAGE_SIZE, 103); // cell content starts at page end

  const key = pageKey128(baseKey, 1);
  const iv = pageIv(1);
  const encryptedHeader = encryptCbc(key, iv, page.subarray(0, 16));
  const encryptedBody = encryptCbc(key, iv, page.subarray(16));
  const encrypted = Buffer.concat([encryptedHeader, encryptedBody]);
  encrypted.copy(encrypted, 8, 16, 24);
  page.subarray(16, 24).copy(encrypted, 16);
  return encrypted;
}

function makeWal(page: Buffer, pageSize: number): Buffer {
  const wal = Buffer.alloc(32 + 24 + pageSize);
  wal.writeUInt32BE(0x377f0682, 0);
  wal.writeUInt32BE(3007000, 4);
  wal.writeUInt32BE(pageSize, 8);
  wal.writeUInt32BE(1, 12);
  wal.writeUInt32BE(0x12345678, 16);
  wal.writeUInt32BE(0x90abcdef, 20);
  const checksum = (offset: number, length: number, seed: [number, number]) => {
    let [s0, s1] = seed;
    for (let i = offset; i < offset + length; i += 8) {
      s0 = (s0 + wal.readUInt32LE(i) + s1) >>> 0;
      s1 = (s1 + wal.readUInt32LE(i + 4) + s0) >>> 0;
    }
    return [s0, s1] as [number, number];
  };
  let sums = checksum(0, 24, [0, 0]);
  wal.writeUInt32BE(sums[0], 24);
  wal.writeUInt32BE(sums[1], 28);
  wal.writeUInt32BE(1, 32);
  wal.writeUInt32BE(1, 36);
  wal.writeUInt32BE(0x12345678, 40);
  wal.writeUInt32BE(0x90abcdef, 44);
  page.copy(wal, 56);
  sums = checksum(32, 8, sums);
  sums = checksum(56, pageSize, sums);
  wal.writeUInt32BE(sums[0], 48);
  wal.writeUInt32BE(sums[1], 52);
  return wal;
}

function makeTwoPageEncryptedDatabase(): Buffer {
  const baseKey = deriveWxSqlite3BaseKey128(PASSPHRASE);
  const pages = [Buffer.alloc(PAGE_SIZE), Buffer.alloc(PAGE_SIZE)];
  const first = pages[0]!;
  SQLITE_HEADER.copy(first);
  first.writeUInt16BE(PAGE_SIZE, 16);
  first[18] = 1;
  first[19] = 1;
  first[21] = 64;
  first[22] = 32;
  first[23] = 32;
  first[100] = 0x0d;
  const second = pages[1]!;
  second[0] = 0x0d;
  second[1] = 0x12;
  second[2] = 0x34;

  return Buffer.concat(
    pages.map((page, index) => {
      const pageNumber = index + 1;
      const key = pageKey128(baseKey, pageNumber);
      const iv = pageIv(pageNumber);
      if (pageNumber !== 1) return encryptCbc(key, iv, page);
      const encryptedHeader = encryptCbc(key, iv, page.subarray(0, 16));
      const encryptedBody = encryptCbc(key, iv, page.subarray(16));
      const encrypted = Buffer.concat([encryptedHeader, encryptedBody]);
      encrypted.copy(encrypted, 8, 16, 24);
      page.subarray(16, 24).copy(encrypted, 16);
      return encrypted;
    }),
  );
}

describe("wxSQLite3 page cipher compatibility", () => {
  test("derives the initial vector from page number plus one", () => {
    expect(pageIv(0).toString("hex")).toBe("055a673593892ddf3ab3b3c621c34802");
    expect(pageIv(1).toString("hex")).toBe("20d7420f9c37a35dca6fe92a1c6999a9");
  });

  test("restores page-one header and verifies a valid passphrase", () => {
    const encrypted = makeEncryptedDatabase();
    const decrypted = decryptWxSqlite3File(encrypted, PASSPHRASE, { pageSize: PAGE_SIZE });

    expect(decrypted.subarray(0, 16)).toEqual(SQLITE_HEADER);
    expect(decrypted.readUInt16BE(16)).toBe(PAGE_SIZE);
    expect(decrypted[100]).toBe(0x0d);
    expect(verifyWxSqlite3Passphrase(encrypted, PASSPHRASE, { pageSize: PAGE_SIZE })).toBe(true);
  });

  test("rejects passphrases whose decrypted page structure is invalid", () => {
    const encrypted = makeEncryptedDatabase();
    expect(
      verifyWxSqlite3Passphrase(encrypted, Buffer.from("wrong-passphrase"), {
        pageSize: PAGE_SIZE,
      }),
    ).toBe(false);
  });

  test("verifies and decrypts with an already-derived 16-byte base key", () => {
    const encrypted = makeEncryptedDatabase();
    const baseKey = deriveWxSqlite3BaseKey128(PASSPHRASE);
    expect(verifyWxSqlite3BaseKey(encrypted, baseKey, { pageSize: PAGE_SIZE })).toBe(true);

    const decrypted = decryptWxSqlite3FileWithBaseKey(encrypted, baseKey, PAGE_SIZE);
    expect(decrypted.subarray(0, 16)).toEqual(SQLITE_HEADER);
    expect(decrypted[100]).toBe(0x0d);
  });

  test("uses the per-page key for pages after page one", () => {
    const encrypted = makeTwoPageEncryptedDatabase();
    const baseKey = deriveWxSqlite3BaseKey128(PASSPHRASE);
    const decrypted = decryptWxSqlite3FileWithBaseKey(encrypted, baseKey, PAGE_SIZE);
    expect(decrypted.subarray(0, 16)).toEqual(SQLITE_HEADER);
    expect(decrypted[PAGE_SIZE]).toBe(0x0d);
    expect(decrypted.subarray(PAGE_SIZE + 1, PAGE_SIZE + 3)).toEqual(Buffer.from([0x12, 0x34]));
  });

  test("rejects base keys that do not match page one", () => {
    const encrypted = makeEncryptedDatabase();
    expect(verifyWxSqlite3BaseKey(encrypted, Buffer.alloc(16, 0x7f), { pageSize: PAGE_SIZE })).toBe(
      false,
    );
  });

  test("applies committed encrypted WAL pages without touching the input buffers", () => {
    const baseKey = deriveWxSqlite3BaseKey128(PASSPHRASE);
    const mainEncrypted = makeEncryptedDatabase(0x11);
    const mainPlain = decryptWxSqlite3FileWithBaseKey(mainEncrypted, baseKey, PAGE_SIZE);
    const walPage = makeEncryptedDatabase(0x5a);
    const wal = makeWal(walPage, PAGE_SIZE);
    const result = applyWxSqlite3WalWithBaseKey(mainPlain, wal, baseKey);

    expect(result.validFrameCount).toBe(1);
    expect(result.committedFrameCount).toBe(1);
    expect(result.transactionCount).toBe(1);
    expect(result.updatedPageCount).toBe(1);
    expect(result.database[200]).toBe(0x5a);
    expect(mainPlain[200]).toBe(0x11);
    expect(wal[56]).toBe(walPage[0]);
  });

  test("rejects WAL files with an invalid header checksum", () => {
    const baseKey = deriveWxSqlite3BaseKey128(PASSPHRASE);
    const mainPlain = decryptWxSqlite3FileWithBaseKey(makeEncryptedDatabase(), baseKey, PAGE_SIZE);
    const wal = makeWal(makeEncryptedDatabase(), PAGE_SIZE);
    wal[24] = wal[24]! ^ 0xff;
    expect(() => applyWxSqlite3WalWithBaseKey(mainPlain, wal, baseKey)).toThrow(
      "WAL header checksum is invalid",
    );
  });
});
