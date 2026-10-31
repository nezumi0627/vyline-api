import { expect, test } from "bun:test";
import { applyNextAccessToken } from "./auth_token.js";

test("next access token becomes active before persistence listeners run", () => {
  const observed: string[] = [];
  const client = {
    authToken: "old-token",
    emit: (_event: "update:authtoken", token: string) => {
      observed.push(client.authToken === token ? "active-before-event" : "stale-during-event");
    },
  };

  applyNextAccessToken(client, "new-token");
  expect(client.authToken).toBe("new-token");
  expect(observed).toEqual(["active-before-event"]);
});
