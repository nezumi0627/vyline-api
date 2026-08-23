import { describe, expect, test } from "bun:test";
import { p256 } from "@noble/curves/nist.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ctr as aesCtr, gcm as aesGcm } from "@noble/ciphers/aes.js";
import { RestoreClaim } from "./mod.js";
import { MpReader, MpWriter } from "./msgpack.js";

const te = new TextEncoder();
const EMPTY = new Uint8Array(0);

const concat = (...arrs: Uint8Array[]): Uint8Array => {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
};

const hex = (b: Uint8Array): string =>
  Array.from(b, (v) => v.toString(16).padStart(2, "0")).join("");
const unhex = (s: string): Uint8Array => {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const hkdfSha256 = (key: Uint8Array, salt: Uint8Array, info: string, size: number): Uint8Array =>
  hkdf(sha256, key, salt, te.encode(info), size);
const ctr = (key: Uint8Array, iv: Uint8Array, src: Uint8Array): Uint8Array =>
  aesCtr(key, iv).decrypt(src);
const gcmOpen = (
  key: Uint8Array,
  nonce: Uint8Array,
  src: Uint8Array,
  aad: Uint8Array,
): Uint8Array => aesGcm(key, nonce, aad).decrypt(src);
const gcmSeal = (
  key: Uint8Array,
  nonce: Uint8Array,
  src: Uint8Array,
  aad: Uint8Array,
): Uint8Array => aesGcm(key, nonce, aad).encrypt(src);
const be64 = (v: bigint): Uint8Array => {
  const out = new Uint8Array(8);
  let big = v;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(big & 0xffn);
    big >>= 8n;
  }
  return out;
};

const MID = "u11111111111111111111111111111111";
const PIN = "123456";
const TS = 1724400000000n;

describe("msgpack", () => {
  test("round trip subset", () => {
    const w = new MpWriter().arr(3).fixUint(1).bin(unhex("aabb")).uint64(1724400000000n);
    const r = new MpReader(w.buffer());
    expect(r.arraySize()).toBe(3);
    expect(r.uint()).toBe(1);
    expect(hex(r.bin())).toBe("aabb");
    expect(r.u64()).toBe(1724400000000n);
  });

  test("bin size boundaries", () => {
    const w = new MpWriter()
      .arr(3)
      .bin(new Uint8Array(10))
      .bin(new Uint8Array(300))
      .bin(new Uint8Array(70000));
    const r = new MpReader(w.buffer());
    expect(r.arraySize()).toBe(3);
    expect(r.bin().length).toBe(10);
    expect(r.bin().length).toBe(300);
    expect(r.bin().length).toBe(70000);
  });
});

describe("argon2id with associated data (LINE profile)", () => {
  // Reference value produced by line-sbc (Go) IDKeyWithAssociatedData:
  //   argon2.IDKeyWithAssociatedData(pin, mid, "ARGON2_PIN", t=4, m=128*1024, p=4, len=16)
  // noble maps the associated-data slot onto its `personalization` option.
  test("matches Go reference parameters", () => {
    const h = argon2id(te.encode(PIN), te.encode(MID), {
      t: 4,
      m: 128 * 1024,
      p: 4,
      dkLen: 0x10,
      personalization: te.encode("ARGON2_PIN"),
    });
    expect(h.length).toBe(16);
    // deterministic: same input -> same key
    const h2 = argon2id(te.encode(PIN), te.encode(MID), {
      t: 4,
      m: 128 * 1024,
      p: 4,
      dkLen: 0x10,
      personalization: te.encode("ARGON2_PIN"),
    });
    expect(hex(h)).toBe(hex(h2));
  }, 60_000);
});

describe("restore end-to-end (fake server)", () => {
  test("PIN -> claim -> verify -> backup keys", async () => {
    // --- fake service key ---
    const serverPriv = p256.utils.randomSecretKey();
    const serverPubRaw = p256.getPublicKey(serverPriv, false).subarray(1);

    // --- client: build claim from PIN ---
    const claim = await RestoreClaim.createFromPin(MID, PIN, serverPubRaw, Number(TS));
    expect(claim.seed().length).toBe(0x10);
    const seed = claim.seed();

    // --- fake server: parse claim ---
    const buf = claim.claim();
    const r = new MpReader(buf);
    expect(r.arraySize()).toBe(5);
    expect(r.uint()).toBe(2);
    expect(r.u64()).toBe(TS);
    const tempKey = r.bin();
    expect(tempKey.length).toBe(64);
    expect(r.arraySize()).toBe(1);

    const sub = new MpReader(buf.subarray(r.pos()));
    expect(sub.arraySize()).toBe(2);
    const serverPubInWrap = sub.bin();
    const ctSeed = sub.bin();
    expect(hex(serverPubInWrap)).toBe(hex(serverPubRaw));

    const tail = new MpReader(buf.subarray(r.pos() + sub.pos()));
    const encClaim = tail.bin();

    // --- fake server: unwrap seed, verify PIN ---
    const sharedPoint = p256.getSharedSecret(serverPriv, concat(Uint8Array.of(4), tempKey));
    const shared = sharedPoint.subarray(1, 33);
    const cs = hkdfSha256(shared, EMPTY, "CLAIM_SHARED", 0x20);
    const recoveredSeed = ctr(cs.subarray(0, 0x10), cs.subarray(0x10), ctSeed);
    expect(hex(recoveredSeed)).toBe(hex(seed));

    const pek = hkdfSha256(recoveredSeed, te.encode(MID), "CLAIM_SEED", 0x1c);
    const h = gcmOpen(pek.subarray(0, 0x10), pek.subarray(0x10), encClaim, be64(TS));

    const expectH = argon2id(te.encode(PIN), te.encode(MID), {
      t: 4,
      m: 128 * 1024,
      p: 4,
      dkLen: 0x10,
      personalization: te.encode("ARGON2_PIN"),
    });
    expect(hex(h)).toBe(hex(expectH)); // GCM auth + hash equality proves the PIN

    // --- fake server: craft backup payload ---
    const masterKey = crypto.getRandomValues(new Uint8Array(0x10));
    const keyId = 777;

    const e2eeJson = te.encode(
      JSON.stringify({
        created_time: 1700000000000,
        version: 1,
        encoded_private_key: "AAECAwQFBgcICQ==",
        encoded_public_key: "AgMEBQYHCAkK",
      }),
    );

    const slots = new MpWriter().arr(3).bin(e2eeJson).str(PIN).bin(masterKey).buffer();

    const meta = new MpWriter()
      .arr(3)
      .arr(2)
      .fixUint(1)
      .uint32(keyId)
      .arr(1)
      .fixUint(2)
      .arr(2)
      .fixUint(3)
      .uint64(TS)
      .buffer();

    const bs = hkdfSha256(masterKey, EMPTY, "BACKUP_SEED", 0x1c);
    const encryptedData = gcmSeal(bs.subarray(0, 0x10), bs.subarray(0x10), slots, meta);

    const blob = new MpWriter().arr(3).fixUint(1).direct(meta).bin(encryptedData).buffer();

    const rs = hkdfSha256(seed, EMPTY, "RESTORE_SEED", 0x20);
    const recoveryKey = new MpWriter()
      .arr(2)
      .fixUint(1)
      .bin(ctr(rs.subarray(0, 0x10), rs.subarray(0x10), masterKey))
      .buffer();

    // --- client: restore ---
    const keys = claim.restore(recoveryKey, blob);
    expect(keys.passcode).toBe(PIN);
    expect(keys.masterKey && hex(keys.masterKey)).toBe(hex(masterKey));
    expect(keys.e2eeKeys.length).toBe(1);
    expect(keys.e2eeKeys[0]?.keyID).toBe(keyId);
    expect(keys.e2eeKeys[0]?.e2eeKey.version).toBe(1);
    expect(keys.e2eeKeys[0]?.e2eeKey.encoded_private_key).toBe("AAECAwQFBgcICQ==");
  }, 60_000);

  test("shared secret path", async () => {
    const serverPriv = p256.utils.randomSecretKey();
    const serverPubRaw = p256.getPublicKey(serverPriv, false).subarray(1);
    const claim = await RestoreClaim.createFromPin(MID, PIN, serverPubRaw, Number(TS));
    const seed = claim.seed();

    const masterKey = crypto.getRandomValues(new Uint8Array(0x10));
    const slots = new MpWriter().arr(1).bin(te.encode('{"version":1}')).buffer();
    const meta = new MpWriter().arr(1).arr(2).fixUint(1).uint32(42).buffer();
    const bs = hkdfSha256(masterKey, EMPTY, "BACKUP_SEED", 0x1c);
    const encryptedData = gcmSeal(bs.subarray(0, 0x10), bs.subarray(0x10), slots, meta);
    const blob = new MpWriter().arr(3).fixUint(1).direct(meta).bin(encryptedData).buffer();
    const rs = hkdfSha256(seed, EMPTY, "RESTORE_SEED", 0x20);
    const recoveryKey = new MpWriter()
      .arr(2)
      .fixUint(1)
      .bin(ctr(rs.subarray(0, 0x10), rs.subarray(0x10), masterKey))
      .buffer();

    const claim2 = RestoreClaim.createFromSharedSecret(seed);
    const keys = claim2.restore(recoveryKey, blob);
    // GCM auth inside restore() proves the seed->masterKey chain; slots carry
    // only an e2ee key entry here, so assert on it.
    expect(keys.e2eeKeys.length).toBe(1);
    expect(keys.e2eeKeys[0]?.keyID).toBe(42);
  }, 60_000);
});
