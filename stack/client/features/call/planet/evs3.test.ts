import { assertEquals, assertThrows } from "@vyline/protocol/stack/assert";
import { Evs3Assembler, packetizeEvs3, parseEvs3, validateVp8 } from "./evs3.ts";

const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (v) => Number.parseInt(v, 16));
const au = hex("3000009d012a800268010000000000000000000000000000");
const delta = new Uint8Array(au); delta[0] |= 1;
const pkt = (payload: Uint8Array, seq: number, timestamp = 90, ssrc = 211) => ({
  payload,
  seq,
  timestamp,
  ssrc,
  marker: Boolean(payload[0] & 4),
});

Deno.test("EVS3 VP8 includes the native 18-bit size prefix only on B packets", () => {
  const vp8 = au;
  const packets = packetizeEvs3(vp8, true, 0x1234);
  assertEquals(packets, [new Uint8Array([...hex("be12340020030600"), ...vp8])]);
  assertEquals(new Evs3Assembler().push(pkt(packets[0], 1))?.data, vp8);
});

Deno.test("EVS3 accepts native VP8 codec flags separately from the 18-bit length", () => {
  const packet = packetizeEvs3(au, true, 1)[0];
  packet[5] |= 8; // Native-executed 0b0600 decodes/re-encodes as raw length 24.
  assertEquals(new Evs3Assembler().push(pkt(packet, 1))?.data, au);
  const withExtension = new Uint8Array([...packet.slice(0, 4), packet[4] | 1,
    1, 0x88, ...new Uint8Array(8), ...packet.slice(5)]);
  assertEquals(parseEvs3(withExtension).offset, 15);
  assertEquals(new Evs3Assembler().push(pkt(withExtension, 1))?.data, au);
});

Deno.test("EVS3 matches Windows native PD fixtures and emits raw VP8", () => {
  for (const [value, begin, end, key] of [
    ["be12340020", true, true, true],
    ["ba12340020", true, false, true],
    ["801234", false, false, false],
    ["841234", false, true, false],
    ["fa12350003010000", true, false, false],
    ["fe12350003010000", true, true, false],
  ] as const) {
    const header = hex(value);
    const parsed = parseEvs3(new Uint8Array([...header, 1]));
    assertEquals(
      [parsed.begin, parsed.end, parsed.key, parsed.offset],
      [begin, end, key, header.length],
    );
    assertEquals(parsed.pictureId, value.includes("1235") ? 0x1235 : 0x1234);
  }
  assertEquals(packetizeEvs3(au, true, 0x1234), [new Uint8Array([...hex("be12340020030600"), ...au])]);
  assertEquals(packetizeEvs3(delta, false, 0x1235), [
    new Uint8Array([...hex("fe12350003010000030600"), ...delta]),
  ]);
});

Deno.test("EVS3 reconstructs VP8 with reordering and sequence wrap", () => {
  const a = new Evs3Assembler();
  const parts = packetizeEvs3(au, true, 0x1234, 8);
  const first = pkt(parts[0], 65535);
  const middle = pkt(parts[1], 0);
  const last = pkt(parts[2], 1);
  assertEquals(a.push(first, 0), undefined);
  assertEquals(a.push(last, 1), undefined);
  assertEquals(a.push(first, 2), undefined);
  assertEquals(a.push(middle, 3), { data: au, key: true, timestamp: 90 });
  assertEquals(a.push(last, 4), undefined);
});

Deno.test("EVS3 drops missing, mismatched, expired and conflicting pictures", () => {
  const packets = packetizeEvs3(new Uint8Array([...au, ...au]), true, 9, 12);
  const first = pkt(packets[0], 1);
  for (const broken of [
    (a: Evs3Assembler) => a.push(pkt(packets[1], 3), 1),
    (a: Evs3Assembler) => a.push(pkt(packets[1], 2, 91), 1),
    (a: Evs3Assembler) => a.push(pkt(packets[1], 2, 90, 212), 1),
    (a: Evs3Assembler) => a.push(pkt(packets[1], 2), 1001),
    (a: Evs3Assembler) => a.push(pkt(new Uint8Array([...packets[0].slice(0, -1), 99]), 1), 1),
  ]) {
    const a = new Evs3Assembler();
    a.push(first, 0);
    broken(a);
    let result;
    for (let i = 2; i < packets.length; i++) {
      result = a.push(pkt(packets[i], i + 1), 10 + i);
      assertEquals(result, undefined);
    }
    assertEquals(result, undefined);
    assertEquals(a.push(pkt(packetizeEvs3(au, true, 10)[0], 50, 180), 1010)?.data, au);
  }
});

Deno.test("EVS3 waits for a key picture after incomplete or entirely missing pictures", () => {
  const a = new Evs3Assembler();
  const fragments = packetizeEvs3(au, true, 1, 12);
  assertEquals(a.push(pkt(fragments[0], 1), 0), undefined);
  assertEquals(a.push(pkt(packetizeEvs3(delta, false, 2)[0], 3, 180), 1), undefined);
  assertEquals(a.push(pkt(packetizeEvs3(au, true, 3)[0], 4, 270), 2)?.data, au);
  assertEquals(a.push(pkt(packetizeEvs3(delta, false, 4)[0], 6, 360), 3), undefined);
});

Deno.test("EVS3 rejects truncated conditional headers, bad extensions and VP8", () => {
  for (const value of [
    "",
    "80",
    "8012",
    "b81234",
    "ba123400",
    "fa123400",
    "fa12340003030300",
    "be123400218001",
    "be123400210081",
  ]) {
    assertThrows(() => parseEvs3(hex(value)));
  }
  assertEquals(parseEvs3(hex("beffff00eb8082aa5501")).offset, 9);
  for (const value of [
    "",
    "000000",
    "00000000",
    "0000000465",
    "0000000165",
    "0000000141",
    "0000000180",
    "000000011c",
    "000000046764001f00",
  ]) {
    assertThrows(() => validateVp8(hex(value)));
  }
  assertThrows(() => packetizeEvs3(new Uint8Array(1024 * 1024 + 1), true, 0));
  assertThrows(() => packetizeEvs3(au, true, 0, 0));
});

Deno.test("EVS3 invalidates a mismatched continuation even if the correct copy follows", () => {
  const a = new Evs3Assembler();
  a.push(pkt(packetizeEvs3(au, true, 1)[0], 0, 90), 0);
  const fragments = packetizeEvs3(delta, false, 2, 12);
  a.push(pkt(fragments[0], 1, 180), 1);
  a.push(pkt(fragments[1], 2, 181), 2);
  assertEquals(a.push(pkt(fragments[1], 2, 180), 3), undefined);
});

Deno.test("VP8 rejects truncated partitions, invalid dimensions and codec/key mismatch", () => {
  validateVp8(au, true);
  validateVp8(delta, false);
  assertThrows(() => validateVp8(au.slice(0, 11), true));
  assertThrows(() => validateVp8(delta.slice(0, 4), false));
  const scaled = au.slice(); scaled[7] |= 0x40;
  validateVp8(scaled, true);
  assertThrows(() => validateVp8(au, false));
  for (const [offset, value] of [[1, 0xff], [3, 0], [7, 0x7f], [9, 0x7f]] as const) {
    const malformed = au.slice(); malformed[offset] = value;
    assertThrows(() => validateVp8(malformed));
  }
  const malformedSize = packetizeEvs3(au, true, 1)[0];
  malformedSize[6]++;
  assertEquals(new Evs3Assembler().push(pkt(malformedSize, 1)), undefined);
  const rotated = packetizeEvs3(au, true, 1)[0]; rotated[4] |= 0x40;
  assertEquals(new Evs3Assembler().push(pkt(rotated, 1))?.rotation, 1);
});

Deno.test("EVS3 retains bounded continuations that arrive before the beginning", () => {
  const a = new Evs3Assembler();
  const parts = packetizeEvs3(au, true, 4, 8);
  assertEquals(a.push(pkt(parts[1], 0), 0), undefined);
  assertEquals(a.push(pkt(parts[0], 65535), 1), undefined);
  assertEquals(a.push(pkt(parts[2], 1), 2)?.data, au);
});

Deno.test("EVS3 cannot reopen completed or invalidated pictures after a newer picture", () => {
  const a = new Evs3Assembler();
  const first = pkt(packetizeEvs3(au, true, 1)[0], 1, 0xfffffff0);
  const next = pkt(packetizeEvs3(au, true, 2)[0], 2, 0x100);
  assertEquals(a.push(first, 0)?.data, au);
  assertEquals(a.push(next, 1)?.data, au);
  assertEquals(a.push(first, 2), undefined);
  assertEquals(a.push(next, 3), undefined);
});
