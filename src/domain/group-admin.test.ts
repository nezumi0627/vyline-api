import { expect, test } from "bun:test";
import { ChatDomain } from "./chat";
import { ContactsDomain } from "./contacts";

test("friend candidates retain every MID independently of profile resolution", async () => {
  const mids = Array.from({ length: 45 }, (_, i) => `u${i.toString(16).padStart(32, "0")}`);
  const contacts = new ContactsDomain({ base: { relation: { getUserFriendIds: async (args: unknown) => {
    expect(args).toEqual({ request: { blockStatus: "ALL" } });
    return { userFriendMids: mids };
  } } } } as never);
  expect(await contacts.listFriendMids()).toEqual(mids);
});

test("invitation cancellation uses the existing nested Talk request and reqSeq", async () => {
  const chatMid = `c${"1".repeat(32)}`;
  const mid = `u${"2".repeat(32)}`;
  let sequence = 7;
  const chat = new ChatDomain({ base: { getReqseq: async () => sequence++, talk: { deleteOtherFromChat: async (args: unknown) => {
    expect(args).toEqual({ request: { reqSeq: 8, chatMid, targetUserMids: [mid] } }); return {};
  }, cancelChatInvitation: async (args: unknown) => {
    expect(args).toEqual({ request: { reqSeq: 7, chatMid, targetUserMids: [mid] } });
    return {};
  } } } } as never);
  await chat.cancelInvitations(chatMid, [mid]);
  await chat.kick(chatMid, mid);
});
