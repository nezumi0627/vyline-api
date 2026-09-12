import { Thrift as thriftDefinition } from "@vyline/line-types/thrift";
import { assertEquals } from "@vyline/protocol/stack/assert";
import { ThriftRenameParser } from "../rename/parser.ts";
import { Protocols } from "./declares.ts";
import { readThrift } from "./read.ts";
import { silentlyUnsendMessage_args } from "./struct.ts";
import { writeThrift } from "./write.ts";

Deno.test("silentlyUnsendMessage encodes the Android 26.13.0 request layout", () => {
  const args = silentlyUnsendMessage_args({
    silentlyUnsendMessageRequest: {
      reqSeq: 42,
      messageId: "1234567890",
    },
  });

  assertEquals(args, [
    [
      12,
      1,
      [
        [8, 1, 42],
        [11, 2, "1234567890"],
      ],
    ],
  ]);

  const parsed = readThrift(
    writeThrift(args, "silentlyUnsendMessage", Protocols[4]),
    Protocols[4],
  );
  assertEquals(parsed._info.fname, "silentlyUnsendMessage");
  assertEquals(parsed.data, { 1: { 1: 42, 2: "1234567890" } });
});

Deno.test("silentlyUnsendMessage result renames server confirmation", () => {
  const parser = new ThriftRenameParser();
  parser.def = thriftDefinition;

  assertEquals(parser.rename_thrift("silentlyUnsendMessage_result", { 0: { 1: true } }), {
    success: { silentUnsend: true },
  });
});
