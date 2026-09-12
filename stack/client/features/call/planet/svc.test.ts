import { assertEquals, assertThrows } from "@vyline/protocol/stack/assert";
import { Evs3Assembler, parseEvs3 } from "./evs3.ts";
import { packetizeSvcVp8, unwrapSvcVp8, parseSvcVfd } from "./svc.ts";

const vp8 = new Uint8Array([0x30, 0, 0, 0x9d, 1, 0x2a, 0x80, 2, 0x68, 1, 0, 0]);

Deno.test("single-layer VFD keeps layer boundaries on every RTP fragment", () => {
  const packets = packetizeSvcVp8(vp8, true, 1, 0xffff, 2, 4, 4);
  assertEquals(packets.length, 3);
  for (let i = 0; i < packets.length; i++) {
    const packet = packets[i];
    // Android 26.14.0 build_vfd 0x866cb4: B/E delimit layer entries, not RTP fragments.
    assertEquals([...packet.extensionData.subarray(2, 6)], [0xd1, 0x2e, 4, 54]);
    assertEquals(parseSvcVfd(packet.extensionData, packet.payload), (0xffff + i) & 0xffff);
    assertEquals(parseEvs3(packet.payload, true).begin, i === 0);
    assertEquals(parseEvs3(packet.payload, true).end, i === packets.length - 1);
  }
});

Deno.test("SVC VP8 matches native profile/VFD fixture and reuses EVS3 reassembly", () => {
  const packets = packetizeSvcVp8(vp8, true, 0x1234, 0x1234, 1);
  assertEquals([...packets[0].payload.slice(5, 14)], [8, 0x81, 40, 3, 52, 0, 0, 0, 15]);
  assertEquals([...packets[0].extensionData], [2, 3, 0xd1, 0x1e, 3, 54, 0x12, 0x34]);
  assertEquals(parseSvcVfd(packets[0].extensionData, packets[0].payload), 0x1234);
  for (const key of [true, false]) {
    const data = vp8.slice();
    if (!key) data[0] |= 1;
    const assembler = new Evs3Assembler();
    assembler.push({
      payload: unwrapSvcVp8(packets[0].payload),
      ssrc: 1,
      seq: 0xffff,
      timestamp: 0,
      marker: true,
    });
    const fragments = packetizeSvcVp8(data, key, 2, 0xffff, 1, 4);
    assertEquals(
      fragments.map((p) => p.extensionData.slice(6)),
      [new Uint8Array([255, 255]), new Uint8Array([0, 0]), new Uint8Array([0, 1])],
    );
    let frame;
    for (const index of [0, 2, 1]) {
      frame = assembler.push({
        payload: unwrapSvcVp8(fragments[index].payload),
        ssrc: 1,
        seq: index,
        timestamp: 90,
        marker: index === fragments.length - 1,
      });
    }
    assertEquals(frame?.data, data);
    assertEquals(frame?.key, key);
  }
});

Deno.test("SVC VP8 rejects unsupported layers/codecs and inconsistent profile length/key", () => {
  const original = packetizeSvcVp8(vp8, true, 1, 1, 1)[0].payload;
  for (const [offset, value] of [
    [8, 1],
    [9, 18],
    [9, 48],
    [9, 0],
    [13, 16],
  ] as const) {
    const payload = original.slice();
    payload[offset] = value;
    assertThrows(() => unwrapSvcVp8(payload));
  }
  assertThrows(() => unwrapSvcVp8(original.slice(0, 13)));
  assertThrows(() => packetizeSvcVp8(vp8, true, 1, -1, 1));
  const packet = packetizeSvcVp8(vp8, true, 1, 1, 2)[0];
  for (const [offset, value] of [
    [0, 4],
    [1, 2],
    [2, 0xc8],
    [3, 0x2f], // Reserved bit, not the independent VFD layer-boundary flag.
    [4, 1],
  ] as const) {
    const vfd = packet.extensionData.slice();
    vfd[offset] = value;
    assertThrows(() => parseSvcVfd(vfd, packet.payload));
  }
  assertThrows(() => parseSvcVfd(new Uint8Array(), packet.payload));
});

Deno.test("group downlink keeps the SVC profile after layered PD extensions without RTP VFD", () => {
  const original = packetizeSvcVp8(vp8, true, 1, 10, 2)[0].payload;
  const layered = new Uint8Array([
    original[0],
    0,
    1,
    0x24,
    0x25,
    0x80,
    4,
    0,
    0,
    0,
    0,
    5,
    2,
    0,
    0,
    8,
    0x81,
    0x48,
    3,
    0x34,
    ...original.subarray(10),
  ]);
  assertThrows(() => parseEvs3(layered)); // Direct-call single-layer contract stays strict.
  assertEquals(parseEvs3(layered, true).spatialId, 2);
  assertEquals(parseEvs3(layered, true).temporalId, 1);
  assertEquals(
    new Evs3Assembler().push({
      payload: unwrapSvcVp8(layered),
      ssrc: 1,
      seq: 10,
      timestamp: 0,
      marker: true,
    })?.data,
    vp8,
  );
  const mismatch = layered.slice();
  mismatch[19] = 0x14;
  assertThrows(() => unwrapSvcVp8(mismatch));
});

Deno.test("VP8A converts its four-byte raw length without changing compressed VP8", () => {
  const packet = packetizeSvcVp8(vp8, true, 7, 10, 2, 1000, 4)[0];
  assertEquals([...packet.payload.subarray(8, 18)], [4, 52, 0, 0, 0, 16, 0, 0, 0, 12]);
  assertEquals(packet.extensionData[4], 4);
  assertEquals(
    new Evs3Assembler().push({
      payload: unwrapSvcVp8(packet.payload),
      ssrc: 1,
      seq: 10,
      timestamp: 0,
      marker: true,
    })?.data,
    vp8,
  );
  const wrong = packet.payload.slice();
  wrong[13]++;
  assertThrows(() => unwrapSvcVp8(wrong));
  assertEquals(parseSvcVfd(new Uint8Array(), packet.payload, true), undefined);
});
