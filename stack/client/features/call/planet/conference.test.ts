import { assertEquals, assertThrows } from "@vyline/protocol/stack/assert";
import { deflateSync } from "node:zlib";
import { encodePb, type PbField } from "./cassini.ts";
import { ConferenceState } from "./conference.ts";

const mid = (n: number) => `u${n.toString(16).padStart(32, "0")}`;
const scalar = (tag: number, value: number): PbField => ({
  tag,
  wireType: 0,
  value: BigInt(value),
});
const bytes = (tag: number, value: Uint8Array): PbField => ({ tag, wireType: 2, value });
const string = (tag: number, value: string) => bytes(tag, new TextEncoder().encode(value));
function member(n: number, connected: boolean, sources: number[] = [n]): Uint8Array {
  return encodePb([
    string(1, mid(n)),
    scalar(2, 3),
    scalar(3, connected ? 1 : 0),
    ...sources.map((ssrc) => bytes(10, encodePb([string(1, "A"), scalar(2, ssrc)]))),
  ]);
}
function notification(version: number, full: boolean, members: Uint8Array[], compressed = false) {
  const message = encodePb([
    bytes(
      1,
      encodePb([scalar(1, full ? 1 : 0), scalar(2, version), ...members.map((m) => bytes(50, m))]),
    ),
  ]);
  return encodePb([
    scalar(1, compressed ? 1 : 0),
    bytes(2, compressed ? deflateSync(message) : message),
  ]);
}

Deno.test("conference FULL/PARTIAL replaces source lists, removes departures and ignores stale versions", () => {
  const state = new ConferenceState();
  assertEquals(state.accept(notification(0, false, [member(1, true)])), true);
  assertEquals(
    state.members.map((m) => m.mid),
    [mid(1)],
  );
  assertEquals(state.accept(notification(1, true, [member(1, true), member(2, true)], true)), true);
  assertEquals(
    state.members.map((m) => m.mid),
    [mid(1), mid(2)],
  );
  assertEquals(state.accept(notification(2, false, [member(1, true, []), member(2, false)])), true);
  assertEquals(state.members, [{ mid: mid(1), connected: true, mediaFlags: 3, sources: [] }]);
  assertEquals(state.accept(notification(1, true, [member(2, true)])), false);
  assertEquals(state.accept(notification(2, false, [member(2, true)])), false);
  assertEquals(state.accept(notification(3, true, [])), true);
  assertEquals(state.members, []);
  assertEquals(state.accept(notification(0, false, [member(1, true)])), true);
  assertEquals(
    state.members.map((m) => m.mid),
    [mid(1)],
  );
});

Deno.test("conference validates atomically and bounds decompression, members and source counts", () => {
  const state = new ConferenceState();
  state.accept(notification(1, true, [member(1, true)]));
  const invalid = [
    notification(2, true, [encodePb([string(1, mid(1))])]), // native requires has_connect
    notification(2, true, [member(1, true), member(1, true)]),
    notification(2, true, [member(1, true, [3]), member(2, true, [3])]),
    notification(2, true, [member(1, true, new Array(33).fill(1))]),
    notification(
      2,
      true,
      Array.from({ length: 513 }, (_, i) => member(i + 1, true)),
    ),
    encodePb([scalar(1, 2), bytes(2, new Uint8Array([1]))]),
    encodePb([scalar(1, 1), bytes(2, deflateSync(new Uint8Array(262145)))]),
    new Uint8Array(262145),
    new Uint8Array([8, 1, 18, 5, 1]),
  ];
  for (const message of invalid) assertThrows(() => state.accept(message));
  assertEquals(
    state.members.map((m) => m.mid),
    [mid(1)],
  );
});

Deno.test("conference seeds existing members from PARTICIPATE contents before notifier deltas", () => {
  const state = new ConferenceState();
  assertEquals(
    state.acceptInfo(encodePb([scalar(1, 1), scalar(2, 42), bytes(50, member(2, true))])),
    true,
  );
  assertEquals(state.accept(notification(43, false, [member(1, true)])), true);
  assertEquals(
    state.members.map((m) => m.mid),
    [mid(2), mid(1)],
  );
  const compressed = deflateSync(encodePb([scalar(1, 1), scalar(2, 44)]));
  assertEquals(state.acceptInfo(compressed, 1), true);
  assertEquals(state.members, []);
  assertThrows(() => state.acceptInfo(deflateSync(new Uint8Array(262145)), 1));
  assertThrows(() => state.acceptInfo(compressed, 2));
});

Deno.test("conference maps video sources to explicit channel IDs with independent versioning", () => {
  const state = new ConferenceState();
  const source = encodePb([string(1, "V"), scalar(2, 33)]);
  const user = encodePb([string(1, mid(1)), scalar(3, 1), bytes(10, source)]);
  state.accept(notification(1, true, [user]));
  assertEquals(state.videoSources, [{ mid: mid(1), ssrc: 33, channel: 0 }]);
  const channel = (version: number, memberState: number, channelId?: number) =>
    encodePb([
      bytes(
        2,
        encodePb([
          bytes(
            2,
            encodePb([
              scalar(1, version),
              ...(channelId === undefined ? [] : [scalar(2, channelId)]),
              bytes(11, encodePb([string(1, mid(1)), scalar(3, memberState), bytes(11, source)])),
            ]),
          ),
        ]),
      ),
    ]);
  assertEquals(state.accept(channel(1, 1, 42)), true);
  assertEquals(state.videoSources, [{ mid: mid(1), ssrc: 33, channel: 42 }]);
  assertEquals(state.accept(channel(1, 0, 42)), false);
  assertEquals(state.accept(channel(2, 0, 42)), true);
  assertEquals(state.videoSources, []);
  assertEquals(state.accept(channel(0, 2, 0)), true); // Explicit 0 is valid, absence is not.
  assertEquals(state.videoSources, [{ mid: mid(1), ssrc: 33, channel: 0 }]);
  assertThrows(() => state.accept(channel(3, 1)));
  assertThrows(() => state.accept(channel(3, 3, 0)));
  state.accept(notification(2, false, [member(1, false)]));
  assertEquals(state.videoSources, []);
});
