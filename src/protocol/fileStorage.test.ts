import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VylineFileStorage } from "./fileStorage.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function permissions(mode: number): number {
  return mode & 0o777;
}

describe("VylineFileStorage credential permissions", () => {
  test("atomically writes protocol storage with private POSIX permissions", async () => {
    const root = await mkdtemp(join(tmpdir(), "vyline-protocol-storage-"));
    roots.push(root);
    const accountDir = join(root, "accounts", "account-a");
    const path = join(accountDir, "protocol.json");
    const storage = new VylineFileStorage(path);

    await Promise.all([
      storage.set("authToken", "secret-token"),
      storage.set("refreshToken", "secret-refresh"),
      storage.set("revision", 2),
    ]);

    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
      authToken: "secret-token",
      refreshToken: "secret-refresh",
      revision: 2,
    });
    expect((await readdir(accountDir)).filter((name) => name.endsWith(".tmp"))).toEqual([]);
    if (process.platform !== "win32") {
      expect(permissions((await stat(accountDir)).mode)).toBe(0o700);
      expect(permissions((await stat(path)).mode)).toBe(0o600);
    }
  });

  test("tightens permissions on existing protocol storage when it is read", async () => {
    const root = await mkdtemp(join(tmpdir(), "vyline-protocol-existing-"));
    roots.push(root);
    const accountDir = join(root, "account-b");
    const path = join(accountDir, "protocol.json");
    await mkdir(accountDir, { recursive: true });
    await writeFile(path, JSON.stringify({ refreshToken: "existing-secret" }));
    if (process.platform !== "win32") {
      await chmod(accountDir, 0o777);
      await chmod(path, 0o644);
    }

    const storage = new VylineFileStorage(path);
    expect(await storage.get("refreshToken")).toBe("existing-secret");
    if (process.platform !== "win32") {
      expect(permissions((await stat(accountDir)).mode)).toBe(0o700);
      expect(permissions((await stat(path)).mode)).toBe(0o600);
    }

    // A replacement must remain private even if an old file was permissive.
    await storage.set("refreshToken", "rotated-secret");
    if (process.platform !== "win32") {
      expect(permissions((await stat(path)).mode)).toBe(0o600);
    }
  });
});
