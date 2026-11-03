import { createCipheriv } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
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

function makeEncryptedDatabase(): Buffer {
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
});
