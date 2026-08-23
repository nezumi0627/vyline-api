/**
 * Go 相互検証用: 固定鍵で v2 PIN claim を生成し、Go verifier (line-sbc cmd/verifyclaim)
 * に食わせる JSON を stdout に出力する。
 *
 * 使い方:
 *   bun run src/sbc/crosscheck.ts > claim.json
 *   cd <line-sbc-src> && ./verifyclaim.exe < claim.json
 */
import { p256 } from "@noble/curves/nist.js";
import { RestoreClaim } from "./mod.js";

const MID = "u81c530b68cc2efdd36911d214bd5f084";
const PIN = "123456";
const TS = 1724400000000n;

const serverPriv = new Uint8Array(32);
for (let i = 0; i < 32; i++) serverPriv[i] = (i * 7 + 3) & 0xff;
const serverPubRaw = p256.getPublicKey(serverPriv, false).subarray(1);

const hex = (b: Uint8Array): string =>
  Array.from(b, (v) => v.toString(16).padStart(2, "0")).join("");

const claim = await RestoreClaim.createFromPin(MID, PIN, serverPubRaw as Uint8Array, Number(TS));

process.stdout.write(
  JSON.stringify({
    mid: MID,
    passcode: PIN,
    ts: TS.toString(),
    serverPriv: hex(serverPriv),
    claim: hex(claim.claim()),
    seed: hex(claim.seed()),
  }),
);
