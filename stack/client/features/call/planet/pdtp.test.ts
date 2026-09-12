import { assertEquals, assertThrows } from "@vyline/protocol/stack/assert";
import { buildPdtp, parsePdtp, PdtpReader, pdtpUint, PdtpReceiver } from "./pdtp.ts";

Deno.test("PDTP validates packet number, service and descending section boundaries", () => {
  const payload = Uint8Array.from([
    0x80,
    0,
    ...new TextEncoder().encode("PLANET"),
    0,
    0x48,
    0,
    5,
    7,
    0,
    0,
    0,
    0,
    2,
    1,
    1,
  ]);
  const packet = parsePdtp(payload, 7);
  assertEquals(packet.number, 7n);
  assertEquals(packet.service, "PLANET");
  assertEquals(
    packet.sections.map((s) => [s.type, [...s.body]]),
    [
      [15, [7, 0, 0, 0, 0]],
      [12, [1, 1]],
    ],
  );
  for (let i = 0; i < payload.length; i++) assertThrows(() => parsePdtp(payload.subarray(0, i), 7));
  assertThrows(() => parsePdtp(Uint8Array.from([...payload, 0]), 7));
  assertThrows(() => parsePdtp(Uint8Array.from([0, 0, 0, 0, 0]), 7));
  const wide = parsePdtp(Uint8Array.from([0xc0, 0, 0, 1, 0, 0, 0, 0, 0]), 9);
  assertEquals(wide.number, (1n << 32n) + 9n);
});

Deno.test("PDTP v62 round trips all widths and rejects truncated integers", () => {
  for (const n of [0n, 63n, 64n, 16383n, 16384n, (1n << 30n) - 1n, 1n << 30n, (1n << 62n) - 1n]) {
    const encoded = pdtpUint(n);
    assertEquals(new PdtpReader(encoded).uint(), n);
    assertThrows(() => new PdtpReader(encoded.subarray(0, encoded.length - 1)).uint());
  }
  assertThrows(() => pdtpUint(-1n));
  assertThrows(() => pdtpUint(1n << 62n));
});

Deno.test("PDTP acknowledges packets and grants absolute credit to opened notifier streams", () => {
  const receiver = new PdtpReceiver();
  const packet = {
    number: 7n,
    service: "PLANET",
    sections: [{ type: 4, body: new Uint8Array([1, 1, 0, 0]) }],
  };
  for (const number of [7n, 0x10001n, 1n << 40n]) {
    const encoded = buildPdtp({ ...packet, number });
    assertEquals(parsePdtp(encoded, Number(number & 65535n)), { ...packet, number });
  }
  const result = receiver.accept(packet, 0);
  assertEquals(result.messages, []);
  assertEquals(
    result.replies.map((r) => [r.service, r.sections.map((s) => s.type)]),
    [
      ["", [15]],
      ["PLANET", [13]],
    ],
  );
  const credit = new PdtpReader(result.replies[1].sections[0].body);
  assertEquals([credit.uint(), credit.uint(), credit.uint()], [1n, 1n, 327680n]);
  credit.end();
  assertEquals(
    receiver.accept(
      { number: 8n, service: "", sections: [{ type: 15, body: new Uint8Array([7, 0, 0, 0]) }] },
      0,
    ).replies,
    [],
  );
  assertThrows(() =>
    receiver.accept({ ...packet, sections: [{ type: 4, body: new Uint8Array([1, 1]) }] }, 0),
  );
});

Deno.test("PDTP reassembles reliable messages out of order without double delivery", () => {
  const receiver = new PdtpReceiver();
  const open = {
    number: 1n,
    service: "PLANET",
    sections: [{ type: 4, body: new Uint8Array([1, 1, 0x12, 0]) }],
  };
  receiver.accept(open, 0);
  const fragment = (pn: bigint, offset: number, flags: number, data: number[]) => ({
    number: pn,
    service: "PLANET",
    sections: [
      {
        type: 1,
        body: Uint8Array.from([
          1,
          1,
          flags,
          ...Array.from({ length: 7 }, (_, i) => 1 << (6 - i))
            .filter((bit) => flags & bit)
            .map(() => 0),
          offset,
          data.length,
          ...data,
        ]),
      },
    ],
  });
  const last = fragment(2n, 2, 0x16, [3, 4]);
  assertEquals(receiver.accept(last, 0).messages, []);
  assertEquals(receiver.accept(fragment(3n, 0, 0x1a, [1, 2]), 0).messages, [
    new Uint8Array([1, 2, 3, 4]),
  ]);
  assertEquals(receiver.accept(last, 0).messages, []);
  assertEquals(receiver.accept(fragment(4n, 4, 0x1e, [5]), 0).messages, [new Uint8Array([5])]);
  assertEquals(receiver.accept(fragment(5n, 0, 0x1e, [9]), 1).messages, [new Uint8Array([9])]);
  const bad = fragment(6n, 5, 0x1e, [6]);
  bad.sections[0].body = bad.sections[0].body.subarray(0, -1);
  assertThrows(() => receiver.accept(bad, 0));
  assertEquals(receiver.accept(fragment(6n, 5, 0x1e, [6]), 0).messages, [new Uint8Array([6])]);
});

Deno.test("PDTP DATA consumes validated records, not the server's approximate section size", () => {
  const data = new Uint8Array(89).fill(7);
  const body = new Uint8Array([1, 1, 0x1e, 0, 0, 0, 0, 0, ...pdtpUint(89n), ...data]);
  const payload = buildPdtp({ number: 1n, service: "PLANET", sections: [{ type: 1, body }] });
  // Native 0x1a0b88 uses record boundaries; live server size is one byte larger.
  payload[12]++;
  const packet = parsePdtp(payload, 1);
  assertEquals(new PdtpReceiver().accept(packet, 0).messages, [data]);
  assertThrows(() => parsePdtp(payload.subarray(0, -1), 1));
});
