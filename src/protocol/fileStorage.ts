/**
 * VylineFileStorage — stack/storage の FileStorage 相当を自前実装
 *
 * 1アカウント = 1 JSON ファイルの単純な KV ストア。書き込みは直列化する
 * (同時書き込みで JSON が壊れないようにキュー化)。
 */

import { randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;

function chmodPrivate(path: string, mode: number, bestEffort = false): void {
  // chmod does not provide the intended ACL guarantee on Windows. Keep the
  // existing Windows behavior and rely on the user's profile ACL there.
  if (process.platform === "win32") return;
  try {
    chmodSync(path, mode);
  } catch (error) {
    if (!bestEffort) throw error;
  }
}

export type StorageValue = string | number | boolean | null | Record<string | number, unknown>;

export class VylineFileStorage {
  private path: string;
  private cache: Record<string, StorageValue> | null = null;
  private writeLock: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.path = path;
  }

  private load(): Record<string, StorageValue> {
    if (this.cache) return this.cache;
    let loaded: Record<string, StorageValue> = {};
    if (existsSync(this.path)) {
      // Older versions created protocol.json with the process umask. Correct
      // existing credential storage before reading it whenever the OS permits.
      chmodPrivate(dirname(this.path), PRIVATE_DIRECTORY_MODE, true);
      chmodPrivate(this.path, PRIVATE_FILE_MODE, true);
      try {
        loaded = JSON.parse(readFileSync(this.path, "utf-8"));
      } catch {
        loaded = {};
      }
    }
    this.cache = loaded;
    return loaded;
  }

  private persist(): Promise<void> {
    // Capture this mutation before queuing the write. A later set/delete must
    // not change the payload of an already queued atomic replacement.
    const payload = JSON.stringify(this.load(), null, 2);
    this.writeLock = this.writeLock
      .catch(() => undefined)
      .then(() => {
        const directory = dirname(this.path);
        mkdirSync(directory, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
        chmodPrivate(directory, PRIVATE_DIRECTORY_MODE);

        // The temporary file lives beside protocol.json, so rename is atomic and
        // cannot cross a Docker bind-mount/filesystem boundary.
        const temporaryPath = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
        let descriptor: number | undefined;
        try {
          descriptor = openSync(temporaryPath, "wx", PRIVATE_FILE_MODE);
          writeFileSync(descriptor, payload, "utf8");
          fsyncSync(descriptor);
          closeSync(descriptor);
          descriptor = undefined;
          chmodPrivate(temporaryPath, PRIVATE_FILE_MODE);
          renameSync(temporaryPath, this.path);
          chmodPrivate(this.path, PRIVATE_FILE_MODE);
        } finally {
          if (descriptor !== undefined) {
            try {
              closeSync(descriptor);
            } catch {
              // Preserve the original write/fsync failure.
            }
          }
          rmSync(temporaryPath, { force: true });
        }
      });
    return this.writeLock;
  }

  async get(key: string): Promise<StorageValue | undefined> {
    return this.load()[key];
  }

  async set(key: string, value: StorageValue): Promise<void> {
    this.load()[key] = value;
    await this.persist();
  }

  async delete(key: string): Promise<void> {
    delete this.load()[key];
    await this.persist();
  }

  async clear(): Promise<void> {
    this.cache = {};
    await this.persist();
  }

  /** 別ストレージへ全キーをコピーする (protocol BaseStorage 互換のため用意) */
  async migrate(target: { set(key: string, value: StorageValue): Promise<void> }): Promise<void> {
    const data = this.load();
    for (const [key, value] of Object.entries(data)) {
      await target.set(key, value);
    }
  }
}
