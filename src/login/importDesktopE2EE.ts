/**
 * Desktop 稼働中メモリ / 抽出済み JSON から E2EE 自己鍵を取り込む
 */

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { BaseClient } from "@vyline/protocol/stack/base";
import type { Client } from "@vyline/protocol/stack";
import { generateKeyPair } from "curve25519-js";
import { verifyE2EEKeyPair } from "../e2ee/primitives.js";
import { selfPubCacheKey } from "../e2ee/pubCacheKeys.js";

type AnyClient = Client | BaseClient;

export interface DesktopE2EEKey {
  keyId: number | string;
  privKey: string;
  pubKey: string;
  e2eeVersion?: number | string;
}

export interface DesktopE2EEKeyDump {
  mid?: string;
  extractedAt?: string;
  keys: DesktopE2EEKey[];
  /** 正規化で除外されたエントリ数 */
  invalidCount?: number;
  /** keyId 重複で落としたエントリ数 */
  duplicateCount?: number;
}

/** SBC クラウドバックアップ復元鍵 (sbc-keys-*.json) の形式 */
export interface SbcBackupKeyFile {
  mid?: string;
  savedAt?: string;
  e2eeKeys: Array<{
    keyID: number | string;
    e2eeKey: {
      created_time?: number;
      encoded_private_key: string;
      encoded_public_key?: string;
      version?: number;
    };
  }>;
}

function asBase(client: AnyClient): BaseClient {
  return "base" in client ? (client as Client).base : (client as BaseClient);
}

/** 既定の抽出ファイルパス */
export function defaultDesktopE2EEKeysPath(dataDir?: string): string {
  const dir = dataDir ?? process.env.VYLINE_DATA_DIR ?? join(process.cwd(), "data");
  return join(dir, "desktop-e2ee-keys.json");
}

/** privKey から Curve25519 公開鍵を導出する（失敗時 null） */
export function derivePubKey(privKey: Buffer): Buffer | null {
  try {
    return Buffer.from(generateKeyPair(Uint8Array.from(privKey)).public);
  } catch {
    return null;
  }
}

/**
 * 様々なソースの鍵エントリを DesktopE2EEKey に正規化する。
 * 対応形式:
 * - Desktop dump: {keyId, privKey, pubKey, e2eeVersion}
 * - SBC 復元鍵:   {keyID, e2eeKey:{encoded_private_key, encoded_public_key?, version?}}
 * pubKey 欠落/不一致時は privKey から再導出する。privKey が使えなければ null。
 */
export function normalizeDesktopE2EEKey(raw: unknown): DesktopE2EEKey | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  let keyId = Number(r.keyId);
  let privB64 = typeof r.privKey === "string" ? r.privKey : "";
  let pubB64 = typeof r.pubKey === "string" ? r.pubKey : "";
  let version = r.e2eeVersion;
  if (!Number.isFinite(keyId) && "keyID" in r) {
    // SBC 形式のフォールバック（フラットな場合も受ける）
    keyId = Number(r.keyID);
  }
  if (typeof r.keyID !== "undefined" && r.e2eeKey && typeof r.e2eeKey === "object") {
    const sbc = r.e2eeKey as Record<string, unknown>;
    keyId = Number(r.keyID);
    privB64 = typeof sbc.encoded_private_key === "string" ? sbc.encoded_private_key : "";
    pubB64 = typeof sbc.encoded_public_key === "string" ? sbc.encoded_public_key : "";
    version = sbc.version;
  }
  if (!Number.isFinite(keyId) || !privB64) return null;
  let priv: Buffer;
  try {
    priv = Buffer.from(privB64, "base64");
  } catch {
    return null;
  }
  if (priv.length !== 32) return null;
  let pub: Buffer | null = null;
  if (pubB64) {
    try {
      const candidate = Buffer.from(pubB64, "base64");
      if (candidate.length === 32 && verifyE2EEKeyPair(priv, candidate)) pub = candidate;
    } catch {
      /* fallthrough to derive */
    }
  }
  if (!pub) pub = derivePubKey(priv);
  if (!pub) return null;
  const numVersion = Number(version ?? 1);
  return {
    keyId,
    privKey: priv.toString("base64"),
    pubKey: pub.toString("base64"),
    e2eeVersion: Number.isFinite(numVersion) ? numVersion : 1,
  };
}

function dedupeKeys(keys: DesktopE2EEKey[]): { keys: DesktopE2EEKey[]; duplicates: number } {
  const byId = new Map<number, DesktopE2EEKey>();
  let duplicates = 0;
  for (const key of keys) {
    const id = Number(key.keyId);
    if (byId.has(id)) duplicates += 1;
    else byId.set(id, key);
  }
  const sortById = (a: DesktopE2EEKey, b: DesktopE2EEKey) => Number(a.keyId) - Number(b.keyId);
  return { keys: [...byId.values()].sort(sortById), duplicates };
}

/** exactOptionalPropertyTypes 対応: undefined を持つ任意フィールドを条件付きで展開する */
function withOptionalMeta(
  keys: DesktopE2EEKey[],
  meta: { mid?: string | undefined; extractedAt?: string | undefined },
  stats?: { invalidCount?: number; duplicateCount?: number },
): DesktopE2EEKeyDump {
  return {
    ...(meta.mid !== undefined ? { mid: meta.mid } : {}),
    ...(meta.extractedAt !== undefined ? { extractedAt: meta.extractedAt } : {}),
    ...(stats?.invalidCount !== undefined ? { invalidCount: stats.invalidCount } : {}),
    ...(stats?.duplicateCount !== undefined ? { duplicateCount: stats.duplicateCount } : {}),
    keys,
  };
}

export function loadDesktopE2EEKeyDump(path: string): DesktopE2EEKeyDump | null {
  if (!existsSync(path)) return null;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as DesktopE2EEKeyDump;
    const list = Array.isArray(raw?.keys) ? raw.keys : [];
    if (!list.length) return null;
    let invalidCount = 0;
    const normalized: DesktopE2EEKey[] = [];
    for (const entry of list) {
      const key = normalizeDesktopE2EEKey(entry);
      if (key) normalized.push(key);
      else invalidCount += 1;
    }
    if (!normalized.length) return null;
    const { keys, duplicates } = dedupeKeys(normalized);
    return withOptionalMeta(keys, raw, {
      invalidCount,
      duplicateCount: duplicates,
    });
  } catch {
    return null;
  }
}

/**
 * SBC クラウドバックアップ復元鍵ファイル群 (sbc-keys-*.json) を読み込む。
 * 新しいものから順にマージし、DesktopE2EEKeyDump 形式で返す。
 */
export function loadSbcBackupKeyDumps(dir: string): DesktopE2EEKeyDump | null {
  if (!existsSync(dir)) return null;
  let files: string[] = [];
  try {
    files = readdirSync(dir)
      .filter((f) => /^sbc-keys-.*\.json$/.test(f))
      .sort()
      .reverse(); // タイムスタンプ降順 = 新しいもの優先
  } catch {
    return null;
  }
  let mid: string | undefined;
  let savedAt: string | undefined;
  const mids = new Set<string>();
  const merged = new Map<number, DesktopE2EEKey>();
  for (const file of files) {
    try {
      const raw = JSON.parse(readFileSync(join(dir, file), "utf8")) as SbcBackupKeyFile;
      if (raw.mid) mids.add(raw.mid);
      const ts = typeof raw.savedAt === "string" ? raw.savedAt : undefined;
      if (ts && (!savedAt || ts > savedAt)) savedAt = ts;
      for (const entry of raw.e2eeKeys ?? []) {
        const key = normalizeDesktopE2EEKey(entry);
        if (key && !merged.has(Number(key.keyId))) merged.set(Number(key.keyId), key);
      }
    } catch {
      /* 壊れたファイルは無視 */
    }
  }
  if (!merged.size) return null;
  if (mids.size === 1) mid = [...mids][0];
  return withOptionalMeta(
    [...merged.values()].sort((a, b) => Number(a.keyId) - Number(b.keyId)),
    { mid, extractedAt: savedAt },
  );
}

/** 2つの dump を keyId ベースでマージする（primary 優先・重複は primary を採用） */
export function mergeDesktopE2EEKeyDumps(
  primary: DesktopE2EEKeyDump,
  extra: DesktopE2EEKeyDump,
): DesktopE2EEKeyDump {
  const seen = new Set(primary.keys.map((k) => Number(k.keyId)));
  const added = extra.keys.filter((k) => !seen.has(Number(k.keyId)));
  const { keys, duplicates } = dedupeKeys([...primary.keys, ...added]);
  return withOptionalMeta(
    keys,
    {
      mid: primary.mid ?? extra.mid,
      extractedAt: primary.extractedAt ?? extra.extractedAt,
    },
    {
      duplicateCount: (primary.duplicateCount ?? 0) + (extra.duplicateCount ?? 0) + duplicates,
      invalidCount: (primary.invalidCount ?? 0) + (extra.invalidCount ?? 0),
    },
  );
}

/**
 * Desktop 抽出鍵を protocol storage にマージする。
 * 既存の一致する鍵は残し、サーバ公開鍵と一致するものだけ採用する。
 */
export async function importDesktopE2EEKeys(
  client: AnyClient,
  dump: DesktopE2EEKeyDump,
): Promise<{ imported: number; skipped: number; keyIds: number[] }> {
  const base = asBase(client);
  if (!base.profile?.mid) await base.talk.getProfile();
  const mid = base.profile?.mid;

  let serverKeys: Array<{
    keyId?: number;
    2?: number;
    keyData?: string | Uint8Array;
    4?: string | Uint8Array;
  }> = [];
  try {
    serverKeys = await base.talk.getE2EEPublicKeys();
  } catch {
    /* offline import: verify local only */
  }

  const serverById = new Map<number, Buffer>();
  for (const sk of serverKeys) {
    const id = Number(sk.keyId ?? sk[2]);
    const data = sk.keyData ?? sk[4];
    if (Number.isFinite(id) && data) {
      serverById.set(id, typeof data === "string" ? Buffer.from(data) : Buffer.from(data));
    }
  }

  let imported = 0;
  let skipped = 0;
  const keyIds: number[] = [];
  let latestServerMatched: DesktopE2EEKey | null = null;

  for (const key of dump.keys) {
    const keyId = Number(key.keyId);
    if (!Number.isFinite(keyId) || !key.privKey || !key.pubKey) {
      skipped += 1;
      continue;
    }
    const priv = Buffer.from(key.privKey, "base64");
    const pub = Buffer.from(key.pubKey, "base64");
    if (!verifyE2EEKeyPair(priv, pub)) {
      base.log("vyline:e2ee", { phase: "desktop-import-bad-pair", keyId });
      skipped += 1;
      continue;
    }
    const serverPub = serverById.get(keyId);
    // サーバに無い keyId も履歴復号用に保存するが、mid 既定には使わない
    if (serverPub && !verifyE2EEKeyPair(priv, serverPub)) {
      base.log("vyline:e2ee", { phase: "desktop-import-server-mismatch", keyId });
      skipped += 1;
      continue;
    }

    const payload = {
      keyId,
      privKey: key.privKey,
      pubKey: serverPub ? serverPub.toString("base64") : key.pubKey,
      e2eeVersion: key.e2eeVersion ?? 1,
    };
    await base.storage.set(`e2eeKeys:${keyId}`, JSON.stringify(payload));
    // 自分が creator のグループ鍵 unwrap 用（peer キャッシュと keyId 衝突しないよう self 名前空間）
    await base.storage.set(selfPubCacheKey(keyId), payload.pubKey);
    imported += 1;
    keyIds.push(keyId);
    if (serverPub) {
      if (!latestServerMatched || keyId > Number(latestServerMatched.keyId)) {
        latestServerMatched = payload;
      }
    }
    base.log("vyline:e2ee", {
      phase: "desktop-import",
      keyId,
      onServer: Boolean(serverPub),
    });
  }

  // mid キーはサーバ登録済み＆一致する最大 keyId（送信時の sender key）
  if (mid && latestServerMatched) {
    await base.storage.set(`e2eeKeys:${mid}`, JSON.stringify(latestServerMatched));
  }

  return { imported, skipped, keyIds };
}
