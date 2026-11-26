import { assertEquals } from "@vyline/protocol/stack/assert";
import { formatException } from "./mod.ts";

Deno.test("formatException — flat TalkException", () => {
  assertEquals(
    formatException({
      code: "INVALID_LENGTH",
      reason: "Invalid Length",
      parameterMap: { LIMIT: "100" },
    }),
    `: INVALID_LENGTH Invalid Length {"LIMIT":"100"}`,
  );
});

Deno.test("formatException — nested under getContactsV3 union keys", () => {
  assertEquals(
    formatException({
      ere: { code: "EXCESSIVE", reason: "too many mids", parameterMap: {} },
    }),
    ": EXCESSIVE too many mids",
  );
});

Deno.test("formatException — numeric code from unmapped enum", () => {
  assertEquals(formatException({ code: 1234, reason: "unknown" }), ": 1234 unknown");
});

Deno.test("formatException — no exception payload", () => {
  assertEquals(formatException({ chats: [] }), "");
  assertEquals(formatException(undefined), "");
});
