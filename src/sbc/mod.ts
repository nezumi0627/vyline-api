/**
 * LINE Secure Backup Client (TypeScript port).
 *
 * Restores E2EE backup keys from a LINE cloud backup using the backup PIN
 * (v2 claim), a password credential (v3 claim), or a previously obtained
 * shared seed.
 */
import { ctr as aesCtr, gcm as aesGcm } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { X509Certificate } from "node:crypto";
import { MpReader, MpWriter } from "./msgpack.js";

const te = new TextEncoder();
const EMPTY = new Uint8Array(0);

export type BackupKeyType = 1 | 2 | 3; // e2eeKey | backupPin | backupMasterKey
export const BACKUP_KEY_TYPE = {
  E2EE_KEY: 1,
  BACKUP_PIN: 2,
  BACKUP_MASTER_KEY: 3,
} as const;

export type PayloadType = 1 | 2; // e2eeKey | initialFullSyncKey
export const PAYLOAD_TYPE = {
  E2EE_KEY: 1,
  INITIAL_FULL_SYNC_KEY: 2,
} as const;

export type E2eeKeyData = {
  created_time: number;
  version: number;
  encoded_private_key: string;
  encoded_public_key: string;
};

export type E2eeKey = { keyID: number; e2eeKey: E2eeKeyData };

export type BackupKeys = {
  e2eeKeys: E2eeKey[];
  passcode?: string;
  masterKey?: Uint8Array;
};

export type PayloadSecret = {
  type: PayloadType;
  key: Uint8Array;
};

// ---- validation ----

const validateMid = (mid: string): boolean => /^u[0-9a-f]{32}$/.test(mid);
const validatePasscode = (passcode: string): boolean => /^\d{6}$/.test(passcode);

// ---- crypto primitives ----

const deriveKey = (key: Uint8Array, salt: Uint8Array, info: string, size: number): Uint8Array =>
  hkdf(sha256, key, salt, te.encode(info), size);

const ctrCrypt = (key: Uint8Array, iv: Uint8Array, src: Uint8Array): Uint8Array =>
  aesCtr(key, iv).decrypt(src); // CTR: encryption == decryption

const aeadEncrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  src: Uint8Array,
  aad: Uint8Array,
): Uint8Array => aesGcm(key, nonce, aad).encrypt(src);

const aeadDecrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  src: Uint8Array,
  aad: Uint8Array,
): Uint8Array => aesGcm(key, nonce, aad).decrypt(src);

const randomBytes = (size: number): Uint8Array => crypto.getRandomValues(new Uint8Array(size));

const hashPasswordArgon2id = (passwd: Uint8Array, mid: string, ad: string): Uint8Array =>
  argon2id(passwd, te.encode(mid), {
    t: 4,
    m: 128 * 1024,
    p: 4,
    dkLen: 0x10,
    personalization: te.encode(ad),
  });

/** Argon2id hash of a PIN ("ARGON2_PIN" domain). */
export const hashPinArgon2id = (pin: Uint8Array, mid: string): Uint8Array =>
  hashPasswordArgon2id(pin, mid, "ARGON2_PIN");

/** Argon2id hash of a v3 password / recovery-code credential. */
export const hashCredentialArgon2id = (
  cred: Uint8Array,
  mid: string,
  factor: "password" | "recoveryCode",
): Uint8Array =>
  hashPasswordArgon2id(
    cred,
    mid,
    factor === "password" ? "V2_ARGON2_PASSWORD" : "V2_ARGON2_RECOVERY",
  );

// ---- P256 helpers ----

/** Extracts the raw P256 public key (64 bytes, no 0x04 prefix) from a PEM certificate. */
export const pubKeyFromCertPem = (pem: string): Uint8Array => {
  const cert = new X509Certificate(pem);
  const jwk = cert.publicKey.export({ format: "jwk" }) as { crv?: string; x?: string; y?: string };
  if (jwk.crv !== "P-256" || !jwk.x || !jwk.y)
    throw new Error("sbc: certificate does not contain a P-256 public key");
  const dec = (s: string): Uint8Array =>
    Uint8Array.from(atob(s.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
  const x = dec(jwk.x);
  const y = dec(jwk.y);
  if (x.length !== 32 || y.length !== 32)
    throw new Error("sbc: certificate P-256 point has invalid length");
  const out = new Uint8Array(64);
  out.set(x, 0);
  out.set(y, 32);
  return out;
};

const stripP256Prefix = (uncompressed: Uint8Array): Uint8Array => {
  if (uncompressed.length !== 65 || uncompressed[0] !== 4)
    throw new Error("sbc: invalid public key");
  return uncompressed.subarray(1);
};

const ecdhSharedSecret = (privRaw: Uint8Array, serverPubRaw: Uint8Array): Uint8Array => {
  const pub = new Uint8Array(65);
  pub[0] = 4;
  pub.set(serverPubRaw, 1);
  const shared = p256.getSharedSecret(privRaw, pub);
  return shared.length === 65 ? shared.subarray(1, 33) : shared.subarray(1);
};

interface KeyEnvelope {
  wrap: Uint8Array;
  tempKey: Uint8Array;
}

const wrapBackupECDHKey = (
  serverPubRaw: Uint8Array,
  seed: Uint8Array,
  info: string,
): KeyEnvelope => {
  const priv = p256.utils.randomSecretKey();
  const epk = stripP256Prefix(p256.getPublicKey(priv, false));
  const secret = ecdhSharedSecret(priv, serverPubRaw);
  const cs = deriveKey(secret, EMPTY, info, 0x20);
  const ciphertext = ctrCrypt(cs.subarray(0, 0x10), cs.subarray(0x10), seed);
  const wrap = new MpWriter().arr(2).bin(serverPubRaw).bin(ciphertext).buffer();
  return { wrap, tempKey: epk };
};

// ---- claim construction (v2: PIN) ----

const marshalClaim = (envelope: KeyEnvelope, enc: Uint8Array, timestamp: bigint): Uint8Array => {
  const w = new MpWriter();
  return w
    .arr(5)
    .fixUint(2)
    .uint64(timestamp)
    .bin(envelope.tempKey)
    .arr(1)
    .direct(envelope.wrap)
    .bin(enc)
    .buffer();
};

const marshalClaimV3 = (
  envelope: KeyEnvelope,
  mid: string,
  enc: Uint8Array,
  factorType: number,
  timestamp: bigint,
): Uint8Array => {
  const w = new MpWriter();
  return w
    .arr(7)
    .fixUint(3)
    .bin(te.encode(mid))
    .uint64(timestamp)
    .bin(envelope.tempKey)
    .arr(1)
    .direct(envelope.wrap)
    .fixUint(factorType)
    .bin(enc)
    .buffer();
};

const makeRestoreClaim = async (
  mid: string,
  passcode: string,
  timestamp: bigint,
  serverPubRaw: Uint8Array,
): Promise<RestoreClaim> => {
  if (!validateMid(mid)) throw new Error("sbc: invalid mid");
  if (!validatePasscode(passcode)) throw new Error("sbc: invalid passcode");
  const seed = randomBytes(0x10);
  const envelope = wrapBackupECDHKey(serverPubRaw, seed, "CLAIM_SHARED");
  const pek = deriveKey(seed, te.encode(mid), "CLAIM_SEED", 0x1c);
  // Argon2id at m=128MiB is CPU heavy (~seconds in JS); kept awaitable so callers
  // can offload to a worker without changing this signature.
  const h = hashPinArgon2id(te.encode(passcode), mid);
  await Promise.resolve();
  const aad = new MpWriter().direct(be64(timestamp)).buffer();
  const enc = aeadEncrypt(pek.subarray(0, 0x10), pek.subarray(0x10), h, aad);
  return new RestoreClaim(marshalClaim(envelope, enc, timestamp), seed);
};

const be64 = (v: bigint): Uint8Array => {
  const out = new Uint8Array(8);
  let big = BigInt(v);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(big & 0xffn);
    big >>= 8n;
  }
  return out;
};

const le16 = (v: number): Uint8Array => Uint8Array.from([v & 0xff, (v >> 8) & 0xff]);
const le64 = (v: number | bigint): Uint8Array => {
  const out = new Uint8Array(8);
  let big = BigInt(v);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(big & 0xffn);
    big >>= 8n;
  }
  return out;
};

// ---- public claim classes ----

// ---- claim construction (v3: password / recovery code) ----

class SecretFactor {
  constructor(
    readonly mid: string,
    readonly cred: string,
    readonly factorType: 1 | 2, // password | recoveryCode
  ) {}

  hashCredential(): Uint8Array {
    return hashCredentialArgon2id(
      te.encode(this.cred),
      this.mid,
      this.factorType === 1 ? "password" : "recoveryCode",
    );
  }
}

const makeRestoreClaimV3 = (
  factor: SecretFactor,
  timestamp: bigint,
  serverPubRaw: Uint8Array,
): RestoreClaimV3 => {
  if (!validateMid(factor.mid)) throw new Error("sbc: invalid mid");
  const seed = randomBytes(0x10);
  const envelope = wrapBackupECDHKey(serverPubRaw, seed, "V2_CLAIM_SHARED");
  const cek = deriveKey(seed, te.encode(factor.mid), "V2_CLAIM_SEED", 0x1c);
  const aad = new MpWriter()
    .direct(le16(3))
    .direct(te.encode(factor.mid))
    .direct(le64(timestamp))
    .direct(envelope.tempKey)
    .direct(le16(factor.factorType))
    .buffer();
  const h = factor.hashCredential();
  const ciphertext = aeadEncrypt(cek.subarray(0, 0x10), cek.subarray(0x10), h, aad);
  const claim = marshalClaimV3(envelope, factor.mid, ciphertext, factor.factorType, timestamp);
  return new RestoreClaimV3(factor.mid, claim, seed);
};

export class SecretFactorClaimBuilder {
  constructor(
    private readonly mid: string,
    private readonly cred: string,
    private readonly factorType: 1 | 2,
  ) {}

  claim(serverCertPemOrPub: string | Uint8Array, timestamp = BigInt(Date.now())): RestoreClaimV3 {
    const pub =
      typeof serverCertPemOrPub === "string"
        ? pubKeyFromCertPem(serverCertPemOrPub)
        : serverCertPemOrPub;
    return makeRestoreClaimV3(
      new SecretFactor(this.mid, this.cred, this.factorType),
      timestamp,
      pub,
    );
  }
}

export const createFromPassword = (mid: string, password: string): SecretFactorClaimBuilder =>
  new SecretFactorClaimBuilder(mid, password, 1);

export const createFromRecoveryCode = (mid: string, code: string): SecretFactorClaimBuilder =>
  new SecretFactorClaimBuilder(mid, code, 2);

// ---- restore ----

type BlobPayload = {
  e2eeKeyIds: number[];
  timestamp: bigint;
  hasBackupPin: boolean;
  hasMasterKey: boolean;
  encryptedData: Uint8Array;
};

const unmarshalBlobPayload = (b: Uint8Array): BlobPayload => {
  const r = new MpReader(b);
  if (r.arraySize() !== 3) throw new Error("sbc/msgpack: blob payload unpack failed");
  const objType = r.uint();
  if (objType !== 1) throw new Error("sbc/msgpack: backup keys contained an unknown object type");
  const elemSize = r.arraySize();

  const payload: BlobPayload = {
    e2eeKeyIds: [],
    timestamp: 0n,
    hasBackupPin: false,
    hasMasterKey: false,
    encryptedData: new Uint8Array(0),
  };
  for (let i = 0; i < elemSize; i++) {
    const v = r.arraySize();
    const keyType = r.uint() as BackupKeyType;
    switch (keyType) {
      case BACKUP_KEY_TYPE.E2EE_KEY:
        if (v !== 2) throw new Error("sbc/msgpack: invalid data");
        payload.e2eeKeyIds.push(r.i32());
        break;
      case BACKUP_KEY_TYPE.BACKUP_PIN:
        if (v !== 1) throw new Error("sbc/msgpack: invalid data");
        payload.hasBackupPin = true;
        break;
      case BACKUP_KEY_TYPE.BACKUP_MASTER_KEY:
        if (v !== 2) throw new Error("sbc/msgpack: invalid data");
        payload.timestamp = r.u64();
        payload.hasMasterKey = true;
        break;
    }
  }
  payload.encryptedData = r.bin();
  return payload;
};

type KeySlots = { e2eeKeys: Uint8Array[]; pin?: string; masterKey?: Uint8Array };

const unmarshalBackupKeySlots = (b: Uint8Array, hasPin: boolean, hasMaster: boolean): KeySlots => {
  const r = new MpReader(b);
  const keySize = r.arraySize() - (hasPin ? 1 : 0) - (hasMaster ? 1 : 0);
  const slots: KeySlots = { e2eeKeys: [] };
  for (let i = 0; i < keySize; i++) slots.e2eeKeys.push(r.bin());
  if (hasPin) slots.pin = r.str();
  if (hasMaster) slots.masterKey = r.bin();
  return slots;
};

const decryptRecoveryKey = (seed: Uint8Array, key: Uint8Array): Uint8Array => {
  const rs = deriveKey(seed, EMPTY, "RESTORE_SEED", 0x20);
  const r = new MpReader(key);
  if (r.arraySize() !== 2) throw new Error("sbc/msgpack: recovery key unpack failed");
  if (r.uint() !== 1) throw new Error("sbc/msgpack: recovery key unpack failed");
  const wrapped = r.bin();
  if (wrapped.length !== 0x10) throw new Error("sbc/msgpack: recovery key unpack failed");
  return ctrCrypt(rs.subarray(0, 0x10), rs.subarray(0x10), wrapped);
};

const generateBackupKeys = (slots: KeySlots, ids: number[]): BackupKeys => {
  if (ids.length !== slots.e2eeKeys.length)
    throw new Error("sbc: key id count does not match key size");
  const keys: E2eeKey[] = slots.e2eeKeys.map((raw, i) => {
    const keyID = ids[i];
    if (keyID === undefined) throw new Error("sbc: key id count does not match key size");
    return { keyID, e2eeKey: JSON.parse(new TextDecoder().decode(raw)) as E2eeKeyData };
  });
  const out: BackupKeys = { e2eeKeys: keys };
  if (slots.pin !== undefined) out.passcode = slots.pin;
  if (slots.masterKey !== undefined) out.masterKey = slots.masterKey;
  return out;
};

const makeRestoreBackupKeys = (
  seed: Uint8Array,
  key: Uint8Array,
  payload: Uint8Array,
): BackupKeys => {
  const masterKey = decryptRecoveryKey(seed, key);
  return decryptBlobWithMaster(masterKey, payload);
};

const decryptBlobWithMaster = (masterKey: Uint8Array, payload: Uint8Array): BackupKeys => {
  const bs = deriveKey(masterKey, EMPTY, "BACKUP_SEED", 0x1c);
  const blob = unmarshalBlobPayload(payload);
  // AAD is the raw msgpack metadata array (element #2 of the blob payload).
  // Recompute it exactly as marshalled on the wire by re-encoding from parsed fields.
  const meta = new MpWriter();
  meta.arr(blob.e2eeKeyIds.length + (blob.hasBackupPin ? 1 : 0) + (blob.hasMasterKey ? 1 : 0));
  for (const keyId of blob.e2eeKeyIds) {
    meta
      .arr(2)
      .fixUint(1)
      .uint32(keyId >>> 0);
  }
  if (blob.hasBackupPin) meta.arr(1).fixUint(BACKUP_KEY_TYPE.BACKUP_PIN);
  if (blob.hasMasterKey)
    meta.arr(2).fixUint(BACKUP_KEY_TYPE.BACKUP_MASTER_KEY).uint64(blob.timestamp);
  const plaintext = aeadDecrypt(
    bs.subarray(0, 0x10),
    bs.subarray(0x10),
    blob.encryptedData,
    meta.buffer(),
  );
  const slots = unmarshalBackupKeySlots(plaintext, blob.hasBackupPin, blob.hasMasterKey);
  return generateBackupKeys(slots, blob.e2eeKeyIds);
};

// ---- payload secrets (v3) ----

type RecoveryKeyV2 = { timestamp: bigint; encryptedKey: Uint8Array };

const unmarshalRecoveryKeyV2 = (b: Uint8Array): RecoveryKeyV2 => {
  const r = new MpReader(b);
  if (r.arraySize() !== 3) throw new Error("sbc/msgpack: recovery key version 2 unpack failed");
  if (r.uint() !== 2) throw new Error("sbc/msgpack: recovery key version 2 unpack failed");
  const timestamp = r.u64();
  const encryptedKey = r.bin();
  if (encryptedKey.length !== 0x20)
    throw new Error("sbc/msgpack: recovery key version 2 unpack failed");
  return { timestamp, encryptedKey };
};

type BackupPayload = {
  payloadType: PayloadType;
  metaData: [number, number];
  nonce: Uint8Array;
  publicKey: Uint8Array;
  data: Uint8Array;
};

const unmarshalBackupPayload = (b: Uint8Array): BackupPayload => {
  const r = new MpReader(b);
  if (r.arraySize() < 5) throw new Error("sbc/msgpack: invalid data");
  if (r.uint() !== 2) throw new Error("sbc/msgpack: backup payload unpack failed");
  const payloadType = r.uint() as PayloadType;
  if (payloadType !== PAYLOAD_TYPE.E2EE_KEY && payloadType !== PAYLOAD_TYPE.INITIAL_FULL_SYNC_KEY)
    throw new Error("sbc/msgpack: backup payload unpack failed");
  const metaData: [number, number] = [r.number64(), r.number64()];
  const nonce = r.bin();
  let publicKey: Uint8Array<ArrayBufferLike> = EMPTY;
  if (payloadType === PAYLOAD_TYPE.E2EE_KEY) publicKey = r.bin();
  const data = r.bin();
  return { payloadType, metaData, nonce, publicKey, data };
};

const decryptPayloadSecret = (masterKey: Uint8Array, payload: Uint8Array): PayloadSecret => {
  const bp = unmarshalBackupPayload(payload);
  const master = deriveKey(masterKey, bp.nonce, "V2_PAYLOAD_MASTER", 0x1c);
  const aad = new MpWriter()
    .direct(le16(2))
    .direct(le16(bp.payloadType))
    .direct(le64(bp.metaData[0]))
    .direct(le64(bp.metaData[1]))
    .direct(bp.payloadType !== PAYLOAD_TYPE.INITIAL_FULL_SYNC_KEY ? bp.publicKey : EMPTY)
    .buffer();
  const content = aeadDecrypt(master.subarray(0, 0x10), master.subarray(0x10), bp.data, aad);
  return { type: bp.payloadType, key: content };
};

const decryptRecoveryKeyV2 = (seed: Uint8Array, mid: string, key: Uint8Array): Uint8Array => {
  const rs = deriveKey(seed, te.encode(mid), "V2_RESTORE_SEED", 0x1c);
  const rk = unmarshalRecoveryKeyV2(key);
  const aad = new MpWriter().direct(le16(2)).direct(le64(rk.timestamp)).buffer();
  return aeadDecrypt(rs.subarray(0, 0x10), rs.subarray(0x10), rk.encryptedKey, aad);
};

// ---- public claim classes ----

export class RestoreClaim {
  constructor(
    private readonly claimBytes: Uint8Array | null,
    private readonly seedBytes: Uint8Array,
  ) {}

  static createFromSharedSecret(secret: Uint8Array): RestoreClaim {
    return new RestoreClaim(null, secret);
  }

  /** Builds a v2 restore claim from MID + 6-digit backup PIN + service certificate. */
  static async createFromPin(
    mid: string,
    passcode: string,
    serverCertPemOrPub: string | Uint8Array,
    timestamp = Date.now(),
  ): Promise<RestoreClaim> {
    const pub =
      typeof serverCertPemOrPub === "string"
        ? pubKeyFromCertPem(serverCertPemOrPub)
        : serverCertPemOrPub;
    return makeRestoreClaim(mid, passcode, BigInt(timestamp), pub);
  }

  restore(key: Uint8Array, payload: Uint8Array): BackupKeys {
    if (this.seedBytes.length === 0) throw new Error("sbc: invalid seed size");
    if (key.length === 0) throw new Error("sbc: invalid key size");
    if (payload.length === 0) throw new Error("sbc: invalid payload size");
    return makeRestoreBackupKeys(this.seedBytes, key, payload);
  }

  seed(): Uint8Array {
    return this.seedBytes.slice();
  }

  claim(): Uint8Array {
    return this.claimBytes?.slice() ?? new Uint8Array(0);
  }
}

export class RestoreClaimV3 {
  constructor(
    readonly mid: string,
    private readonly claimBytes: Uint8Array,
    private readonly seedBytes: Uint8Array,
  ) {}

  restore(key: Uint8Array, payload: Uint8Array): PayloadSecret {
    if (key.length === 0) throw new Error("sbc: invalid key size");
    if (payload.length === 0) throw new Error("sbc: invalid payload size");
    if (key.length !== 0x10) {
      if (this.seedBytes.length !== 0)
        return decryptPayloadSecret(decryptRecoveryKeyV2(this.seedBytes, this.mid, key), payload);
      throw new Error("sbc: invalid seed size");
    }
    return decryptPayloadSecret(key, payload);
  }

  seed(): Uint8Array {
    return this.seedBytes.slice();
  }

  claim(): Uint8Array {
    return this.claimBytes.slice();
  }
}

export { MpReader, MpWriter } from "./msgpack.js";
