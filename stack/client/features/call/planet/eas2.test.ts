import { assertEquals, assertThrows } from "@vyline/protocol/stack/assert";
import { depacketizeEas2, packetizeEas2 } from "./eas2.ts";
import { packetizeEas2Frames } from "./eas2.ts";
import { opusCodecFactory } from "../opus.ts";

Deno.test("EAS2 native single-frame speech and silence headers reconstruct Opus", () => {
  for (const outer of [0x00, 0x10, 0x70, 0xf8]) {
    for (const inner of [0xf8, 0xf9]) {
      assertEquals(depacketizeEas2(new Uint8Array([outer, inner, 0xff, 0xfd])), [
        new Uint8Array([0xf8, 0xff, 0xfd]),
      ]);
    }
  }
  assertEquals(
    packetizeEas2(new Uint8Array([0xf8, 0xff, 0xfd])),
    new Uint8Array([0x10, 0xf9, 0xff, 0xfd]),
  );
  assertThrows(() => packetizeEas2(new Uint8Array([0xfb, 2, 1, 2])));
});

Deno.test("EAS2 CELT pairs skip speech mask, hybrid pairs do not", () => {
  assertEquals(depacketizeEas2(new Uint8Array([0x10, 0xfb, 2, 0xc0, 0x11, 0x12, 0x21, 0x22])), [
    new Uint8Array([0xf8, 0x11, 0x12]),
    new Uint8Array([0xf8, 0x21, 0x22]),
  ]);
  assertEquals(depacketizeEas2(new Uint8Array([0x10, 0x7b, 2, 0x11, 0x21])), [
    new Uint8Array([0x78, 0x11]),
    new Uint8Array([0x78, 0x21]),
  ]);
});

Deno.test("EAS2 packetizes group 40ms pairs without raw Opus framing", () => {
  const celt = [new Uint8Array([0xf8, 0x11, 0x12]), new Uint8Array([0xf8, 0x21, 0x22])];
  assertEquals(
    packetizeEas2Frames(celt),
    new Uint8Array([0x10, 0xfb, 2, 0xc0, 0x11, 0x12, 0x21, 0x22]),
  );
  for (const frames of [
    celt,
    [new Uint8Array([0x78, 0x11]), celt[1]],
    [new Uint8Array([0xf8, ...new Uint8Array(256)]), celt[1]],
    Array.from({ length: 6 }, () => celt[0]),
  ]) {
    assertEquals(depacketizeEas2(packetizeEas2Frames(frames)), frames);
  }
  assertEquals(packetizeEas2Frames([celt[0]]), packetizeEas2(celt[0]));
  for (const frames of [
    [],
    new Array(7).fill(celt[0]),
    [new Uint8Array()],
    [new Uint8Array([0xfb, 2, 1, 2])],
  ])
    assertThrows(() => packetizeEas2Frames(frames));
});

Deno.test("EAS2 mixed configs repeat final config and parse VBR lengths", () => {
  assertEquals(
    depacketizeEas2(new Uint8Array([0x20, 0x7a, 0xfb, 0x83, 0xc0, 1, 2, 0x11, 0x21, 0x22, 0x31])),
    [
      new Uint8Array([0x78, 0x11]),
      new Uint8Array([0xf8, 0x21, 0x22]),
      new Uint8Array([0xf8, 0x31]),
    ],
  );
  const large = new Uint8Array([0x10, 0xfb, 0x82, 0xc0, 252, 1, ...new Uint8Array(256), 0x22]);
  const frames = depacketizeEas2(large);
  assertEquals(frames[0].length, 257);
  assertEquals(frames[1], new Uint8Array([0xf8, 0x22]));
});

Deno.test("EAS2 rejects truncated, reserved, excessive or impossible frame layouts", () => {
  for (const bytes of [
    [],
    [0],
    [0, 0xfa],
    [0, 0xfb],
    [0, 0xfb, 2],
    [0, 0xfb, 0],
    [0, 0xfb, 49],
    [0, 0xfb, 0x42],
    [0, 0xfa, 0xfb, 1, 0],
    [0, 0xfb, 2, 0xc0, 1],
    [0, 0xfb, 0x82, 0xc0, 252],
    [0, 0xfb, 0x82, 0xc0, 9, 1, 2],
    [0, 0xf9, ...new Uint8Array(1276)],
  ]) {
    assertThrows(() => depacketizeEas2(new Uint8Array(bytes)));
  }
});

Deno.test("EAS2 preserves actual 20ms codec audio through native single and paired layouts", async () => {
  const codec = await opusCodecFactory();
  const encoder = codec.newEncoder({
    sampleRate: 48000,
    channels: 1,
    frameDurationMs: 20,
    vbr: false,
  });
  const original = codec.newDecoder({ sampleRate: 48000, channels: 1 });
  const native = codec.newDecoder({ sampleRate: 48000, channels: 1 });
  try {
    for (let index = 0; index < 50; index++) {
      const samples = Int16Array.from({ length: 960 }, (_, i) =>
        Math.round(7000 * Math.sin((2 * Math.PI * 440 * (i + index * 960)) / 48000)),
      );
      const opus = encoder.encode({ samples, sampleRate: 48000, channels: 1 })!;
      const frame = depacketizeEas2(packetizeEas2(opus))[0];
      assertEquals(frame, opus);
      assertEquals(native.decode(frame)?.samples, original.decode(opus)?.samples);
      const isCelt = opus[0] >= 0x80;
      const body = opus.subarray(1);
      const pair = new Uint8Array([
        0x20,
        (opus[0] & 0xfc) | 3,
        2,
        ...(isCelt ? [0xc0] : []),
        ...body,
        ...body,
      ]);
      for (const item of depacketizeEas2(pair)) {
        assertEquals(native.decode(item)?.samples, original.decode(opus)?.samples);
      }
    }
  } finally {
    encoder.close?.();
    original.close?.();
    native.close?.();
  }
});
