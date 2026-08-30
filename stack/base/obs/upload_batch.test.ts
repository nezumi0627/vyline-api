import { assert, assertEquals } from "@vyline/protocol/stack/assert";
import { test } from "bun:test";
import { Buffer } from "node:buffer";
import { LineObs } from "./mod.ts";

type UploadCall = {
  data: Blob;
  addHeaders?: Record<string, string>;
  params?: Record<string, string | undefined>;
};

function decodeTalkMeta(value: string): Record<string, string> {
  const outer = JSON.parse(Buffer.from(value, "base64").toString("utf8")) as {
    message: string;
  };
  const data = Buffer.from(outer.message, "base64");
  let offset = 0;
  assertEquals(data.readUInt8(offset++), 13); // MAP
  assertEquals(data.readInt16BE(offset), 18);
  offset += 2;
  assertEquals(data.readUInt8(offset++), 11); // STRING key
  assertEquals(data.readUInt8(offset++), 11); // STRING value
  const size = data.readInt32BE(offset);
  offset += 4;
  const result: Record<string, string> = {};

  const readString = () => {
    const length = data.readInt32BE(offset);
    offset += 4;
    const value = data.subarray(offset, offset + length).toString("utf8");
    offset += length;
    return value;
  };

  for (let index = 0; index < size; index++) {
    result[readString()] = readString();
  }
  return result;
}

function makeObs(gid = "628271567210283486") {
  const calls: UploadCall[] = [];
  const obs = new LineObs({
    authToken: "test-token",
    profile: { mid: "u-sender" },
    getReqseqs: async (_name: string, count: number) =>
      Array.from({ length: count }, (_, index) => 100 + index),
  } as never);
  obs.uploadObjectForService = (async (options: UploadCall) => {
    calls.push(options);
    const headers = new Headers();
    headers.set("x-line-message-gid", gid);
    return {
      objId: `message-${calls.length}`,
      objHash: "",
      headers,
    };
  }) as never;
  return { obs, calls };
}

test("uploadObjTalkBatch — grouped images inherit server-issued GID", async () => {
  const { obs, calls } = makeObs();
  const blobs = [
    new Blob([new Uint8Array([1, 2, 3])], { type: "image/png" }),
    new Blob([new Uint8Array([4, 5, 6])], { type: "image/png" }),
    new Blob([new Uint8Array([7, 8, 9])], { type: "image/png" }),
  ];

  const result = await obs.uploadObjTalkBatch(
    "u-recipient",
    blobs.map((data, index) => ({ type: "image", data, filename: `${index + 1}.png` })),
  );

  assertEquals(result.length, 3);
  assertEquals(calls.length, 3);
  for (let index = 0; index < calls.length; index++) {
    const call = calls[index]!;
    assert(call.data === blobs[index]);
    assertEquals(call.params?.reqseq, String(100 + index));
    assertEquals(call.addHeaders?.["X-Line-Mid"], "u-sender");
    assertEquals(call.addHeaders?.["Upload-Draft-Interop-Version"], "6");
    assertEquals(call.addHeaders?.["Upload-Complete"], "?1");
    const meta = decodeTalkMeta(call.addHeaders?.["X-Talk-Meta"] ?? "");
    assertEquals(meta.GTOTAL, "3");
    assertEquals(meta.GSEQ, String(index + 1));
    assertEquals(meta.GID, index === 0 ? "0" : "628271567210283486");
  }
});

test("uploadObjTalkBatch — missing first response GID stops the remaining group", async () => {
  const calls: UploadCall[] = [];
  const obs = new LineObs({
    authToken: "test-token",
    profile: { mid: "u-sender" },
    getReqseqs: async () => [200, 201, 202],
  } as never);
  obs.uploadObjectForService = (async (options: UploadCall) => {
    calls.push(options);
    return { objId: "message-1", objHash: "", headers: new Headers() };
  }) as never;

  const result = await obs.uploadObjTalkBatch(
    "u-recipient",
    [1, 2, 3].map((value) => ({
      type: "image" as const,
      data: new Blob([new Uint8Array([value])], { type: "image/png" }),
    })),
  );

  assertEquals(calls.length, 1);
  assertEquals(result.length, 3);
  assert("error" in result[1]!);
  assert("error" in result[2]!);
});
