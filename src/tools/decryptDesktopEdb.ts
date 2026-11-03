/**
 * decryptDesktopEdb.ts
 *
 * LINE Desktop .edb (wxSQLite3) 復号を試みる。
 *
 * 手順:
 * 1. 明示同意後、指定した LINE.exe の _Codec baseKey 候補をメモリから収集
 * 2. .edb を共有オープンで読み取り
 * 3. 候補で page1 検証 → 成功したら .sqlite に書き出し
 *
 * Usage:
 *   bun run src/tools/decryptDesktopEdb.ts
 *   bun run src/tools/decryptDesktopEdb.ts --pid <LINE.exe PID> --accept-risk
 *   bun run src/tools/decryptDesktopEdb.ts --passphrase <32hex>
 *   bun run src/tools/decryptDesktopEdb.ts --edb <path> --out <path>
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  openSync,
  readSync,
  closeSync,
  fstatSync,
} from "node:fs";
import { join, basename, dirname, resolve as resolvePath } from "node:path";
import { homedir } from "node:os";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import {
  decryptWxSqlite3File,
  decryptWxSqlite3FileWithBaseKey,
  isLikelyWxSqlite3,
  tryPassphraseVariants,
  verifyWxSqlite3BaseKey,
  verifyWxSqlite3Passphrase,
} from "../desktop/wxSqlite3.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0) return process.argv[i + 1];
  return undefined;
}

function lineDataDbDir(): string {
  const local = process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local");
  return join(local, "LINE", "Data", "db");
}

function findMainEdb(): string | null {
  const dir = lineDataDbDir();
  if (!existsSync(dir)) return null;
  const { readdirSync, statSync } = require("node:fs") as typeof import("node:fs");
  const files = readdirSync(dir)
    .filter(
      (f) =>
        f.endsWith(".edb") &&
        !f.startsWith("album_") &&
        !f.startsWith("chatStats_") &&
        !f.startsWith("keep_"),
    )
    .map((f) => {
      const p = join(dir, f);
      return { p, size: statSync(p).size };
    })
    .sort((a, b) => b.size - a.size);
  return files[0]?.p ?? null;
}

/** Read file even if LINE has it locked (Windows share read). */
function readShared(path: string): Buffer {
  const fd = openSync(path, "r");
  try {
    const st = fstatSync(fd);
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, Math.min(1024 * 1024, st.size - off), off);
      if (n <= 0) break;
      off += n;
    }
    return buf.subarray(0, off);
  } finally {
    closeSync(fd);
  }
}

const MEMORY_SCAN_TERMS = [
  "メモリ走査の利用条件",
  "LINE Desktopの指定プロセスのメモリを読み取り、wxSQLite3の鍵候補を取得してローカルEDBの復号を試みます。メモリ内に認証情報等が含まれる可能性があります。",
  "鍵候補は画面・ログ・ファイルへ出力しません。通信もしません。復号に成功した場合は、会話内容を含む平文SQLiteファイルを指定先へ保存します。",
  "所有または利用権限のあるアカウント・端末のデータだけに使用してください。データのバックアップと出力先の保護は利用者が行い、本機能は無保証・自己責任で利用します。",
  "Vyline開発者は、本機能の利用によるデータ損失・漏えい・アカウント制限等について、適用法令で許される範囲を超える責任を負いません。",
].join("\n");

async function confirmMemoryScanTerms(): Promise<boolean> {
  console.error(MEMORY_SCAN_TERMS);
  if (process.argv.includes("--accept-risk")) return true;
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.error("非対話実行では --accept-risk を付けて利用条件に同意してください。");
    return false;
  }

  const readline = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await readline.question("利用条件に同意して続行しますか？ [y/N] ");
    return answer.trim().toLowerCase() === "y";
  } finally {
    readline.close();
  }
}

function isHexByte(value: number): boolean {
  return (
    (value >= 0x30 && value <= 0x39) ||
    (value >= 0x61 && value <= 0x66) ||
    (value >= 0x41 && value <= 0x46)
  );
}

function parseCandidateLines(output: Buffer): Buffer[] {
  const candidates: Buffer[] = [];
  let start = 0;
  for (let end = 0; end <= output.length; end++) {
    if (end !== output.length && output[end] !== 0x0a) continue;
    let lineEnd = end;
    if (lineEnd > start && output[lineEnd - 1] === 0x0d) lineEnd--;
    if (lineEnd - start === 32) {
      const line = output.subarray(start, lineEnd);
      if (line.every(isHexByte)) candidates.push(Buffer.from(line.toString("ascii"), "hex"));
    }
    start = end + 1;
  }
  return candidates;
}

type MemoryScanResult = {
  candidates: Buffer[];
  status: "ok" | "no-process" | "multiple-processes" | "wrong-process" | "error";
};

function scanPassphrasesFromMemory(requestedPid: number): MemoryScanResult {
  if (process.platform !== "win32") return { candidates: [], status: "error" };
  const ps = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
public class MemScan {
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int a, bool b, int pid);
  [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int n, out int read);
  [DllImport("kernel32.dll")] static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION m, int size);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
    public UIntPtr RegionSize; public uint State; public uint Protect; public uint Type;
  }
  const int PROCESS_VM_READ = 0x0010; const int PROCESS_QUERY_INFORMATION = 0x0400;
  static bool IsKey(byte[] b, int i) {
    if (b[i] != 1 || b[i+1] != 0 || b[i+2] != 0 || b[i+3] != 0 ||
        b[i+4] != 1 || b[i+5] != 0 || b[i+6] != 0 || b[i+7] != 0 ||
        b[i+24] != 1 || b[i+25] != 0 || b[i+26] != 0 || b[i+27] != 0) return false;
    bool nonzero = false; int distinct = 0; var seen = new bool[256];
    for (int k = 0; k < 16; k++) {
      byte x = b[i+8+k];
      if (x == 0 || x != b[i+28+k]) return false;
      nonzero = true;
      if (!seen[x]) { seen[x] = true; distinct++; }
    }
    return nonzero && distinct >= 8;
  }
  static bool IsLineInstall(Process p) {
    try {
      var image = System.IO.Path.GetFullPath(p.MainModule.FileName);
      var installRoot = System.IO.Path.GetFullPath(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LINE", "bin")) + System.IO.Path.DirectorySeparatorChar;
      return image.StartsWith(installRoot, StringComparison.OrdinalIgnoreCase) &&
        String.Equals(System.IO.Path.GetFileName(image), "LINE.exe", StringComparison.OrdinalIgnoreCase);
    } catch { return false; }
  }
  public static List<string> Scan(int requestedPid) {
    var found = new HashSet<string>();
    Process[] processes;
    if (requestedPid > 0) {
      Process selected;
      try { selected = Process.GetProcessById(requestedPid); }
      catch { return new List<string> { "__NO_LINE_PROCESS__" }; }
      if (!String.Equals(selected.ProcessName, "LINE", StringComparison.OrdinalIgnoreCase) || !IsLineInstall(selected))
        return new List<string> { "__WRONG_PROCESS__" };
      processes = new[] { selected };
    } else {
      processes = Process.GetProcessesByName("LINE");
      if (processes.Length > 1) return new List<string> { "__MULTIPLE_LINE_PROCESSES__" };
      if (processes.Length == 1 && !IsLineInstall(processes[0])) return new List<string> { "__WRONG_PROCESS__" };
    }
    if (processes.Length == 0) return new List<string> { "__NO_LINE_PROCESS__" };
    foreach (var p in processes) {
      var h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, p.Id);
      if (h == IntPtr.Zero) continue;
      long addr = 0; var mbi = new MEMORY_BASIC_INFORMATION();
      var buf = new byte[1024 * 1024];
      while (addr < 0x7FFFFFFFFFFF) {
        if (VirtualQueryEx(h, (IntPtr)addr, out mbi, Marshal.SizeOf(mbi)) == 0) break;
        long size = (long)mbi.RegionSize;
        if (mbi.State == 0x1000 && (mbi.Protect == 0x04 || mbi.Protect == 0x02 || mbi.Protect == 0x40 || mbi.Protect == 0x20)) {
          long remaining = size; long off = 0;
          while (remaining > 0) {
            int chunk = (int)Math.Min(remaining, buf.Length);
            int read; if (ReadProcessMemory(h, (IntPtr)(addr + off), buf, chunk, out read) && read > 32) {
              for (int i = 0; i + 44 <= read; i += 4) {
                if (!IsKey(buf, i)) continue;
                found.Add(BitConverter.ToString(buf, i + 8, 16).Replace("-", "").ToLowerInvariant());
                if (found.Count > 5000) { CloseHandle(h); return new List<string>(found); }
              }
            }
            off += chunk; remaining -= chunk;
          }
        }
        long next = addr + size; if (next <= addr) break; addr = next;
      }
      CloseHandle(h);
      Array.Clear(buf, 0, buf.Length);
    }
    return new List<string>(found);
  }
}
"@
$targetPid = [int]$env:VYLINE_MEMORY_SCAN_PID
[MemScan]::Scan($targetPid) | ForEach-Object { $_ }
`;
  const r = spawnSync("powershell.exe", ["-NoProfile", "-Command", ps], {
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    timeout: 120_000,
    windowsHide: true,
    env: { ...process.env, VYLINE_MEMORY_SCAN_PID: String(requestedPid) },
  });
  const stdout = Buffer.isBuffer(r.stdout) ? r.stdout : Buffer.from(r.stdout ?? "");
  const stderr = Buffer.isBuffer(r.stderr) ? r.stderr : Buffer.from(r.stderr ?? "");
  if (r.error) {
    stdout.fill(0);
    stderr.fill(0);
    return { candidates: [], status: "error" };
  }
  const hasMarker = (marker: string) => stdout.includes(Buffer.from(marker, "ascii"));
  let status: MemoryScanResult["status"] = "ok";
  if (hasMarker("MULTIPLE_LINE_PROCESSES")) status = "multiple-processes";
  else if (hasMarker("WRONG_PROCESS")) status = "wrong-process";
  else if (hasMarker("NO_LINE_PROCESS")) status = "no-process";
  else if (r.status !== 0) status = "error";
  const candidates = status === "ok" ? parseCandidateLines(stdout) : [];
  stdout.fill(0);
  stderr.fill(0);
  return { candidates, status };
}

async function main() {
  const forced = arg("passphrase");
  if (!forced && !(await confirmMemoryScanTerms())) {
    console.error("利用条件への同意が確認できないため、メモリを走査せず終了しました。");
    process.exitCode = 4;
    return;
  }

  const requestedPid = Number(arg("pid") ?? 0);
  if (!Number.isSafeInteger(requestedPid) || requestedPid < 0) {
    console.error("--pid には0以上の整数を指定してください。");
    process.exitCode = 1;
    return;
  }

  const edbPath = arg("edb") ?? findMainEdb();
  if (!edbPath || !existsSync(edbPath)) {
    console.error("No .edb found. Pass --edb <path> or start LINE Desktop.");
    process.exit(1);
  }
  console.log("Reading encrypted EDB file.");

  const file = readShared(edbPath);
  console.log("size:", file.length, "wxSQLite3-like:", isLikelyWxSqlite3(file));
  console.log("hdr16-24:", file.subarray(16, 24).toString("hex"));

  // resolve relative to repo
  const dataDir = join(import.meta.dirname ?? ".", "../../../../backend/data/edb-export");
  const destDir = arg("out-dir") ?? dataDir;

  const scan = forced
    ? { candidates: [Buffer.from(forced, "utf8")], status: "ok" as const }
    : scanPassphrasesFromMemory(requestedPid);
  const candidates = scan.candidates;
  if (scan.status !== "ok") {
    const messages = {
      "no-process": "LINE Desktopのプロセスが見つかりません。起動後に再実行してください。",
      "multiple-processes":
        "LINE Desktopが複数起動しています。対象PIDを --pid で指定してください。",
      "wrong-process": "指定PIDはLINE Desktopではありません。LINE.exeのPIDを指定してください。",
      error: "Windowsのメモリ走査を開始できませんでした。",
      ok: "",
    };
    console.error(messages[scan.status]);
    file.fill(0);
    process.exitCode = 2;
    return;
  }
  let hit: { key: Buffer; quirk: boolean; pageSize: number; baseKey: boolean } | null = null;
  let plain: Buffer | undefined;
  try {
    console.log("key candidates found:", candidates.length);
    if (candidates.length === 0) {
      console.error("No candidates. Start LINE.exe and re-run, or pass --passphrase.");
      process.exitCode = 2;
      return;
    }

    const encodedPageSize = file.length >= 18 ? file.readUInt16BE(16) : 0;
    const detectedPageSize = encodedPageSize === 1 ? 65536 : encodedPageSize;
    const variants = forced ? tryPassphraseVariants(forced) : [];
    try {
      outer: for (const cand of candidates) {
        if (forced) {
          for (const variant of variants) {
            for (const quirk of [true, false]) {
              if (verifyWxSqlite3Passphrase(file, variant, { lineQuirk: quirk })) {
                hit = {
                  key: Buffer.from(variant),
                  quirk,
                  pageSize: detectedPageSize,
                  baseKey: false,
                };
                break outer;
              }
            }
          }
        } else {
          if (verifyWxSqlite3BaseKey(file, cand)) {
            hit = {
              key: Buffer.from(cand),
              quirk: false,
              pageSize: detectedPageSize,
              baseKey: true,
            };
            break;
          }
        }
      }
    } finally {
      for (const variant of variants) variant.fill(0);
    }

    if (!hit) {
      console.error(
        "No key verified against page1. Candidate count only; no key material was saved.",
      );
      process.exitCode = 3;
      return;
    }

    plain = hit.baseKey
      ? decryptWxSqlite3FileWithBaseKey(file, hit.key, hit.pageSize)
      : decryptWxSqlite3File(file, hit.key, {
          lineQuirk: hit.quirk,
          pageSize: hit.pageSize,
        });
    const outPath = resolvePath(
      arg("out") ?? join(destDir, basename(edbPath).replace(/\.edb$/i, ".sqlite")),
    );
    const sourcePath = resolvePath(edbPath);
    if (outPath.toLowerCase() === sourcePath.toLowerCase()) {
      console.error("出力先に元のEDBと同じパスは指定できません。");
      process.exitCode = 5;
      return;
    }
    if (existsSync(outPath)) {
      console.error("出力先が既に存在します。別の --out または --out-dir を指定してください。");
      process.exitCode = 5;
      return;
    }
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, plain, { flag: "wx" });
    console.log("decrypted →", outPath);
    console.log("header:", plain.subarray(0, 16).toString("utf8"));
  } finally {
    for (const candidate of candidates) candidate.fill(0);
    hit?.key.fill(0);
    file.fill(0);
    plain?.fill(0);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
