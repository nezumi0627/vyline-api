import { expect, test } from "bun:test";
import { callSetupFailure } from "./transport.ts";

test("non-success setup response identifies a busy peer immediately", () => {
  expect(callSetupFailure({ result: 0, relCode: 486, relPhrase: "busy" })?.message)
    .toBe("PLANET call released: busy (486)");
  expect(callSetupFailure({ result: 0, relCode: 0 })).toBeNull();
});
