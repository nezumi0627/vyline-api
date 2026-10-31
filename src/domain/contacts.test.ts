import { expect, test } from "bun:test";
import { ContactsDomain } from "./contacts.js";

test("deleting a friend sends the LINE contact-delete setting for that MID", async () => {
  let actual: unknown;
  const mid = `u${"a".repeat(32)}`;
  const domain = new ContactsDomain({
    base: {
      getReqseq: async () => 17,
      talk: {
        updateContactSetting: async (input: unknown) => {
          actual = input;
        },
      },
    },
  } as never);

  await domain.delete(mid);

  expect(actual).toEqual({
    reqSeq: 17,
    mid,
    flag: "CONTACT_SETTING_DELETE",
    value: "true",
  });
});
