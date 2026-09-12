import { assertEquals, assertThrows } from "@vyline/protocol/stack/assert";
import { buildRtp, parseRtp, deriveSrtpContext, srtpEncrypt, srtpDecrypt } from "../srtp.ts";
import { buildGroupVsd, readPlanetRtpExtension, unpackXrtp } from "./xrtp.ts";

Deno.test("Group VSD carries distinct signal classification and measured levels", () => {
  const silence = { level: 127, signal: 0 as const };
  const active = { level: 57, signal: 2 as const };
  assertEquals([...buildGroupVsd([silence, silence])], [1, 2, 0xc0, 0x40, 127, 0, 0, 0]);
  assertEquals([...buildGroupVsd([active, active])], [1, 2, 0xc0, 0x68, 57, 0, 0, 0]);
  assertEquals(
    [...buildGroupVsd([silence, { level: 70, signal: 1 }])],
    [1, 2, 0xc0, 0x44, 70, 0, 0, 0],
  );
  assertThrows(() => buildGroupVsd([{ level: 128, signal: 2 }, active]));
  assertThrows(() => buildGroupVsd([{ level: NaN, signal: 2 }, active]));
});

function inner(ssrc = 1, size = 13): Uint8Array {
  return buildRtp({
    payloadType: 96,
    ssrc,
    seq: 7,
    timestamp: 960,
    payload: new Uint8Array(size - 12).fill(9),
  });
}

function outer(lengths: number[], packets: Uint8Array[], extensionPrefix: number[] = []) {
  const body = [...lengths, ...(lengths.length % 2 ? [0] : [])];
  const extension = [...extensionPrefix, 3, body.length / 2, ...body];
  while (extension.length % 4) extension.push(0);
  return buildRtp({
    payloadType: 96,
    ssrc: 100,
    seq: 1,
    timestamp: 960,
    payload: new Uint8Array(packets.flatMap((p) => Array.from(p))),
    extensionProfile: 0x0240,
    extensionData: new Uint8Array(extension),
  });
}

Deno.test("XRTP authenticates outer once and separates complete plaintext RTP by SSRC", async () => {
  const a = inner(11),
    b = inner(22, 300);
  const packet = outer([13, 0x41, 0x2c], [a, b], [0, 1, 1, 0x40, 0x7f]);
  const key = new Uint8Array(30).fill(9);
  const encrypted = await srtpEncrypt(await deriveSrtpContext(key), packet);
  const decrypted = await srtpDecrypt(await deriveSrtpContext(key), encrypted);
  assertEquals(unpackXrtp(parseRtp(decrypted)), [parseRtp(a), parseRtp(b)]);
  assertEquals(unpackXrtp(parseRtp(a)), [parseRtp(a)]);
  for (const encoded of [
    [0x80, 0, 1, 0x2c],
    [0xc0, 0, 0, 0, 0, 0, 1, 0x2c],
  ]) {
    assertEquals(unpackXrtp(parseRtp(outer(encoded, [b]))), [parseRtp(b)]);
  }
});

Deno.test("XRTP rejects oversized, truncated, duplicate and inconsistent layouts atomically", () => {
  const invalid = [
    outer([], []),
    outer([0, 13], [inner()]),
    outer([13, 0, 0, 0], [inner()]),
    outer([0x40], [inner()]),
    outer([0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], [inner()]),
    outer([12], [inner()]),
    outer([14], [inner()]),
    outer([11], [inner(1, 12)]),
    outer([0x46, 0x41], [inner(1, 1601)]),
    outer(
      new Array(17).fill(13),
      Array.from({ length: 17 }, () => inner()),
    ),
    outer([13], [inner()], [3, 1, 13, 0]),
    outer([13], [inner()], [8, 30]),
  ];
  const badVersion = inner();
  badVersion[0] = 0;
  invalid.push(outer([13], [badVersion]));
  for (const packet of invalid) assertThrows(() => unpackXrtp(parseRtp(packet)));
});

Deno.test("PLANET common channel fields precede numbered RTP extensions", () => {
  const packet = inner(11);
  const rtp = parseRtp(
    buildRtp({
      payloadType: 96,
      ssrc: 100,
      seq: 1,
      timestamp: 960,
      payload: packet,
      extensionProfile: 0x0272,
      extensionData: new Uint8Array([0, 0, 0, 7, 0, 0, 0, 42, 3, 1, 13, 0]),
    }),
  );
  assertEquals(readPlanetRtpExtension(rtp)?.sourceChannel, 7);
  assertEquals(readPlanetRtpExtension(rtp)?.channel, 42);
  assertEquals(unpackXrtp(rtp), [parseRtp(packet)]);
  for (const profile of [0x0271, 0x0260, 0x026f]) {
    assertThrows(() => readPlanetRtpExtension({ ...rtp, extensionProfile: profile }));
  }
});
