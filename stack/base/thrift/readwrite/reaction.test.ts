import { expect, test } from "bun:test";
import { ReactionType, CancelReactionRequest } from "./struct";
import { ThriftRenameParser } from "../rename/parser";
import { Thrift } from "@vyline/line-types/thrift";

test("owned emoji uses Android jf/ke paidReactionType fields and preserves version", () => {
  expect(ReactionType({ paidReactionType: {
    productId: "670e0cce840a8236ddd4ee4c", emojiId: "143", resourceType: 2, version: 123,
  } })).toEqual([[12, 2, [
    [11, 1, "670e0cce840a8236ddd4ee4c"], [11, 2, "143"], [8, 3, 2], [10, 4, 123],
  ]]]);
  expect(ReactionType({ predefinedReactionType: "NICE" })).toEqual([[8, 1, 2]]);
  expect(CancelReactionRequest({ reqSeq: 3, messageId: 123n })).toEqual([[8, 1, 3], [10, 2, 123n]]);
  const parser = new ThriftRenameParser();
  parser.def = Thrift;
  expect(parser.rename_thrift("ReactionType", { 1: 2 })).toEqual({ predefinedReactionType: "NICE" });
  expect(parser.rename_thrift("ReactionType", { 2: { 1: "670e0cce840a8236ddd4ee4c", 2: "143", 3: 2, 4: 123 } }))
    .toEqual({ paidReactionType: { productId: "670e0cce840a8236ddd4ee4c", emojiId: "143", resourceType: 2, version: 123 } });
});
