/**
 * wxSQLite3 AES-128-CBC page decrypt (LINE Desktop .edb)
 *
 * Based on Kang et al. Electronics 2024, 13(7), 1325
 * "Forensic Analysis of wxSQLite3-Encrypted Databases and Its Application"
 *
 * LINE quirk (paper §5.3.2): uses the server passphrase (32 hex chars) rather
 * than the padded passphrase for RC4 Step2 / concat Step3.
 */

import { createCipheriv, createDecipheriv, createHash, createHmac } from "node:crypto";

const PADDING = Buffer.from(
  "28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A",
  "hex",
);

function md5(data: Buffer): Buffer {
  return createHash("md5").update(data).digest();
}

function md5N(data: Buffer, n: number): Buffer {
  let h = data;
  for (let i = 0; i < n; i++) h = md5(h);
  return h;
}

/** RC4 encrypt (same as decrypt) */
function rc4(key: Buffer, data: Buffer): Buffer {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i]! + key[i % key.length]!) & 0xff;
    const t = S[i]!;
    S[i] = S[j]!;
    S[j] = t;
  }
  const out = Buffer.alloc(data.length);
  let ii = 0;
  j = 0;
  for (let k = 0; k < data.length; k++) {
    ii = (ii + 1) & 0xff;
    j = (j + S[ii]!) & 0xff;
    const t = S[ii]!;
    S[ii] = S[j]!;
    S[j] = t;
    out[k] = data[k]! ^ S[(S[ii]! + S[j]!) & 0xff]!;
  }
  return out;
}

function padPassphrase(passphrase: Buffer): Buffer {
  const out = Buffer.alloc(32);
  const m = Math.min(passphrase.length, 32);
  passphrase.copy(out, 0, 0, m);
  if (m < 32) PADDING.copy(out, m, 0, 32 - m);
  return out;
}

/**
 * LINE-modified 128-bit base key (paper Algorithm 3 + LINE quirk).
 * passphrase = 32 hex chars as ASCII (or raw 16 bytes).
 */
export function deriveWxSqlite3BaseKey128(passphrase: Buffer, lineQuirk = true): Buffer {
  const padded = padPassphrase(passphrase);
  // Step1: inter_k from padding hashed MD5 × 51
  const interK = md5N(PADDING, 51);

  // Step2: RC4 × 20 — LINE uses original passphrase, wxSQLite3 uses padded
  let msg: Buffer = lineQuirk ? Buffer.from(passphrase) : Buffer.from(padded);
  if (msg.length !== 32) {
    msg = padPassphrase(msg);
  }
  for (let i = 0; i < 20; i++) {
    const rc4Key = Buffer.alloc(16);
    for (let k = 0; k < 16; k++) rc4Key[k] = interK[k]! ^ i;
    msg = Buffer.from(rc4(rc4Key, msg));
  }
  const interV = msg;

  // Step3: MD5(passphrase||inter_v) × 51 — LINE uses original passphrase
  const left = lineQuirk ? passphrase : padded;
  const concat = Buffer.concat([
    left.length >= 32 ? left.subarray(0, 32) : padPassphrase(left),
    interV,
  ]);
  // if passphrase shorter, pad left to match paper concat size
  const left32 = left.length >= 32 ? left.subarray(0, 32) : padPassphrase(left);
  const concat2 = Buffer.concat([left32, interV.subarray(0, 32)]);
  return md5N(concat2.length === concat.length ? concat2 : Buffer.concat([left32, interV]), 51);
}

function modmult(a: number, b: number, c: number, m: number, s: number): number {
  // Algorithm 1 MODMULT from paper
  const q = Math.floor(s / a);
  const r = s % a;
  const t = b * r - c * q;
  if (t >= 0) return t;
  return t + m;
}

/** Page IV = MD5(concat of 4 MODMULT outputs), pageNumber LE u32 */
export function pageIv(pageNumber: number): Buffer {
  const a = 52774;
  const b = 40692;
  const c = 3791;
  const m = 2147483399;
  // wxSQLite3's sqlite3mcGenerateInitialVector() starts from seed + 1.
  let s = (pageNumber + 1) >>> 0;
  const parts: Buffer[] = [];
  for (let i = 0; i < 4; i++) {
    s = modmult(a, b, c, m, s) >>> 0;
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(s, 0);
    parts.push(buf);
  }
  return md5(Buffer.concat(parts));
}

export function pageKey128(baseKey: Buffer, pageNumber: number): Buffer {
  const pn = Buffer.alloc(4);
  pn.writeUInt32LE(pageNumber >>> 0, 0);
  return md5(Buffer.concat([baseKey, pn, Buffer.from("sAlT", "ascii")]));
}

function aes128CbcDecrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const decipher = createDecipheriv("aes-128-cbc", key, iv);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

const SQLITE_HEADER = Buffer.from("SQLite format 3\0", "utf8");

export function isLikelyWxSqlite3(file: Buffer): boolean {
  if (file.length < 32) return false;
  // offsets 16-23 remain plaintext-ish page meta for wxSQLite3
  // not starting with "SQLite format 3"
  return !file.subarray(0, 16).equals(SQLITE_HEADER);
}

/**
 * Verify passphrase by decrypting first page and checking SQLite header.
 */
export function verifyWxSqlite3Passphrase(
  file: Buffer,
  passphrase: Buffer,
  opts?: { lineQuirk?: boolean; pageSize?: number },
): boolean {
  const lineQuirk = opts?.lineQuirk ?? true;
  const encodedPageSize = file.length >= 18 ? file.readUInt16BE(16) : 0;
  const detectedPageSize = encodedPageSize === 1 ? 65536 : encodedPageSize;
  const pageSize = opts?.pageSize ?? detectedPageSize;
  if (file.length < pageSize) return false;
  try {
    const header = file.subarray(16, 24);
    const encodedPageSize = header.readUInt16BE(0);
    const actualPageSize = encodedPageSize === 1 ? 65536 : encodedPageSize;
    if (
      actualPageSize !== pageSize ||
      ![512, 1024, 2048, 4096, 8192, 16384, 32768, 65536].includes(actualPageSize) ||
      ![1, 2].includes(header[2]!) ||
      ![1, 2].includes(header[3]!) ||
      header[5] !== 64 ||
      header[6] !== 32 ||
      header[7] !== 32
    ) {
      return false;
    }

    const base = deriveWxSqlite3BaseKey128(passphrase, lineQuirk);
    const key = pageKey128(base, 1);
    const iv = pageIv(1);
    const page = Buffer.from(file.subarray(0, pageSize));
    const encryptedMeta = Buffer.from(page.subarray(8, 16));
    const clearMeta = Buffer.from(page.subarray(16, 24));
    encryptedMeta.copy(page, 16);
    const body = aes128CbcDecrypt(key, iv, page.subarray(16));
    if (!body.subarray(0, 8).equals(clearMeta)) return false;

    // wxSQLite3 encrypts page-one's 16-byte SQLite header separately and
    // moves the first encrypted body bytes into the 8-byte gap at 8..15.
    // Validate the decrypted b-tree page header before accepting the key.
    const btreeType = body[84]; // absolute page offset 100
    return btreeType === 0x02 || btreeType === 0x05 || btreeType === 0x0a || btreeType === 0x0d;
  } catch {
    return false;
  }
}

/** Verify an already-derived wxSQLite3 16-byte base key against page one. */
export function verifyWxSqlite3BaseKey(
  file: Buffer,
  baseKey: Buffer,
  opts?: { pageSize?: number },
): boolean {
  const encodedPageSize = file.length >= 18 ? file.readUInt16BE(16) : 0;
  const pageSize = opts?.pageSize ?? (encodedPageSize === 1 ? 65536 : encodedPageSize);
  if (baseKey.length !== 16 || file.length < pageSize) return false;
  let derivedKey: Buffer | undefined;
  let page: Buffer | undefined;
  let encryptedMeta: Buffer | undefined;
  let clearMeta: Buffer | undefined;
  let body: Buffer | undefined;
  try {
    const header = file.subarray(16, 24);
    const encodedPageSize = header.readUInt16BE(0);
    const actualPageSize = encodedPageSize === 1 ? 65536 : encodedPageSize;
    if (
      actualPageSize !== pageSize ||
      ![512, 1024, 2048, 4096, 8192, 16384, 32768, 65536].includes(actualPageSize) ||
      ![1, 2].includes(header[2]!) ||
      ![1, 2].includes(header[3]!) ||
      header[5] !== 64 ||
      header[6] !== 32 ||
      header[7] !== 32
    )
      return false;

    derivedKey = pageKey128(baseKey, 1);
    const iv = pageIv(1);
    page = Buffer.from(file.subarray(0, pageSize));
    encryptedMeta = Buffer.from(page.subarray(8, 16));
    clearMeta = Buffer.from(page.subarray(16, 24));
    encryptedMeta.copy(page, 16);
    body = aes128CbcDecrypt(derivedKey, iv, page.subarray(16));
    const valid = body.subarray(0, 8).equals(clearMeta);
    const btreeType = body[84];
    return (
      valid &&
      (btreeType === 0x02 || btreeType === 0x05 || btreeType === 0x0a || btreeType === 0x0d)
    );
  } catch {
    return false;
  } finally {
    derivedKey?.fill(0);
    page?.fill(0);
    encryptedMeta?.fill(0);
    clearMeta?.fill(0);
    body?.fill(0);
  }
}

export function decryptWxSqlite3File(
  file: Buffer,
  passphrase: Buffer,
  opts?: { lineQuirk?: boolean; pageSize?: number },
): Buffer {
  const lineQuirk = opts?.lineQuirk ?? true;
  let pageSize = opts?.pageSize ?? 0;
  const base = deriveWxSqlite3BaseKey128(passphrase, lineQuirk);

  // detect page size from plaintext bytes 16-17 (big-endian in SQLite header)
  if (!pageSize) {
    const be = file.readUInt16BE(16);
    pageSize = be === 1 ? 65536 : be;
    if (![512, 1024, 2048, 4096, 8192, 16384, 32768, 65536].includes(pageSize)) {
      throw new Error(
        "Invalid wxSQLite3 page size; specify pageSize explicitly if this is a legacy database",
      );
    }
  }

  const out = Buffer.alloc(file.length);
  const pageCount = Math.floor(file.length / pageSize);
  for (let p = 1; p <= pageCount; p++) {
    const start = (p - 1) * pageSize;
    const enc = Buffer.from(file.subarray(start, start + pageSize));
    const key = pageKey128(base, p);
    const iv = pageIv(p);
    if (p === 1) {
      // wxSQLite3 encrypts the SQLite header separately. Bytes 8..15 hold
      // the encrypted body bytes displaced from 16..23; the clear header
      // metadata at 16..23 is used to validate and restore the page.
      const clearMeta = Buffer.from(file.subarray(16, 24));
      file.copy(enc, 16, 8, 16);
      const body = aes128CbcDecrypt(key, iv, enc.subarray(16));
      if (!body.subarray(0, 8).equals(clearMeta)) {
        throw new Error(
          "wxSQLite3 page-one metadata check failed; incorrect passphrase or unsupported format",
        );
      }
      SQLITE_HEADER.copy(out, start);
      body.copy(out, start + 16);
      clearMeta.copy(out, start + 16);
      continue;
    }
    const plain = aes128CbcDecrypt(key, iv, enc);
    plain.copy(out, start);
  }
  // trailing bytes
  if (pageCount * pageSize < file.length) {
    file.copy(out, pageCount * pageSize, pageCount * pageSize);
  }
  return out;
}

/** Decrypt a wxSQLite3 database with an already-derived 16-byte base key. */
export function decryptWxSqlite3FileWithBaseKey(
  file: Buffer,
  baseKey: Buffer,
  requestedPageSize = 0,
): Buffer {
  if (baseKey.length !== 16) throw new Error("wxSQLite3 base key must be exactly 16 bytes");
  let pageSize = requestedPageSize;
  if (!pageSize) {
    const encoded = file.readUInt16BE(16);
    pageSize = encoded === 1 ? 65536 : encoded;
  }
  if (!verifyWxSqlite3BaseKey(file, baseKey, { pageSize })) {
    throw new Error("wxSQLite3 page-one verification failed for the supplied base key");
  }

  const out = Buffer.alloc(file.length);
  const pageCount = Math.floor(file.length / pageSize);
  for (let pageNumber = 1; pageNumber <= pageCount; pageNumber++) {
    const offset = (pageNumber - 1) * pageSize;
    const encryptedPage = Buffer.from(file.subarray(offset, offset + pageSize));
    const key = pageKey128(baseKey, pageNumber);
    const iv = pageIv(pageNumber);
    if (pageNumber === 1) {
      const clearMeta = Buffer.from(file.subarray(16, 24));
      file.copy(encryptedPage, 16, 8, 16);
      const body = aes128CbcDecrypt(key, iv, encryptedPage.subarray(16));
      body.copy(out, 16);
      SQLITE_HEADER.copy(out, 0);
      clearMeta.copy(out, 16);
      body.fill(0);
    } else {
      const plain = aes128CbcDecrypt(key, iv, encryptedPage);
      plain.copy(out, offset);
      plain.fill(0);
    }
    key.fill(0);
    encryptedPage.fill(0);
  }
  const remainder = pageCount * pageSize;
  if (remainder < file.length) file.copy(out, remainder, remainder);
  return out;
}

/** Try passphrase as 32-char hex ASCII or 16 raw bytes */
export function tryPassphraseVariants(raw: string | Buffer): Buffer[] {
  const out: Buffer[] = [];
  if (typeof raw === "string") {
    const s = raw.trim();
    out.push(Buffer.from(s, "utf8"));
    if (/^[0-9a-fA-F]{32}$/.test(s)) {
      out.push(Buffer.from(s, "hex"));
    }
  } else {
    out.push(raw);
    if (raw.length === 16) {
      out.push(Buffer.from(raw.toString("hex"), "utf8"));
    }
  }
  return out;
}

// silence unused import warning helpers
void createCipheriv;
void createHmac;
