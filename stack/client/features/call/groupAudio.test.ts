import { assertEquals } from "@vyline/protocol/stack/assert";
import type { CodecFactory } from "./audio.ts";
import { GroupAudioMixer } from "./groupAudio.ts";

Deno.test("group mixer isolates decoders, aligns speakers and bounds late/duplicate packets", () => {
  let created = 0,
    closed = 0;
  const codecs: CodecFactory = {
    newEncoder() {
      throw new Error("receive only");
    },
    newDecoder() {
      created++;
      let value = 0;
      return {
        decode(data) {
          value += data[0];
          return { samples: new Int16Array(960).fill(value), sampleRate: 48000, channels: 1 };
        },
        close() {
          closed++;
        },
      };
    },
  };
  const mixer = new GroupAudioMixer(codecs);
  const packet = (ssrc: number, timestamp: number, value: number) => ({
    ssrc,
    timestamp,
    frames: [new Uint8Array([value])],
  });
  mixer.push(packet(1, 0xfffffc40, 10), 0);
  mixer.push(packet(2, 777, 20), 0);
  assertEquals(mixer.read(40), undefined);
  assertEquals(mixer.read(60)?.samples[0], 30);
  assertEquals(created, 2);
  mixer.push(packet(1, 0xfffffc40, 99), 20); // duplicate must not change codec state
  mixer.push(packet(1, 0, 1), 20); // rollover
  mixer.push(packet(2, 1737, 2), 20);
  assertEquals(mixer.read(80)?.samples[0], 33);
  assertEquals(mixer.read(80), undefined); // no repeated playout
  assertEquals(mixer.read(100), undefined);
  mixer.remove(1);
  assertEquals(closed, 1);
  for (let ssrc = 3; ssrc < 100; ssrc++) mixer.push(packet(ssrc, 100, 1), 100);
  assertEquals(created, 31); // 30 retained decoders max
  mixer.read(31_000);
  assertEquals(closed, created);
  mixer.close();
  mixer.close();
  assertEquals(closed, created);
});

Deno.test("group mixer clips summed PCM and expires buffered sound without catch-up bursts", () => {
  let closed = 0;
  const mixer = new GroupAudioMixer({
    newEncoder() {
      throw new Error("receive only");
    },
    newDecoder() {
      return {
        decode() {
          return { samples: new Int16Array(1920).fill(25000), sampleRate: 48000, channels: 1 };
        },
        close() {
          closed++;
        },
      };
    },
  });
  for (const ssrc of [1, 2]) mixer.push({ ssrc, timestamp: 0, frames: [new Uint8Array([1])] }, 0);
  assertEquals(mixer.read(60)?.samples[0], 32767);
  assertEquals(mixer.read(120), undefined); // second half already late, don't queue it now
  mixer.close();
  assertEquals(closed, 2);
  mixer.push({ ssrc: 3, timestamp: 0, frames: [new Uint8Array([1])] }, 140);
  assertEquals(mixer.read(200), undefined);
});
