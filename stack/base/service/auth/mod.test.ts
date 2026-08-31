import { assertEquals } from "../../../assert.ts";
import { test } from "bun:test";
import type { BaseClient } from "../../core/mod.js";
import { MemoryStorage } from "../../storage/memory.ts";
import { AuthService } from "./mod.ts";

function createService(refreshResult: Record<string, unknown>) {
  const storage = new MemoryStorage();
  const emitted: Array<[string, unknown]> = [];
  const client = {
    storage,
    authToken: "old-access",
    emit(type: string, data: unknown) {
      emitted.push([type, data]);
    },
  } as unknown as BaseClient;
  const service = new AuthService(client);
  let refreshCalls = 0;
  service.refresh = async () => {
    refreshCalls++;
    return refreshResult as never;
  };
  return { service, storage, client, emitted, getRefreshCalls: () => refreshCalls };
}

test("tryRefreshToken persists rotated refresh token and expiry", async () => {
  const { service, storage, client, emitted } = createService({
    accessToken: "new-access",
    refreshToken: "new-refresh",
    tokenIssueTimeEpochSec: 1_000,
    durationUntilRefreshInSec: 3_600,
  });
  await storage.set("refreshToken", "old-refresh");

  await service.tryRefreshToken();

  assertEquals(client.authToken, "new-access");
  assertEquals(await storage.get("refreshToken"), "new-refresh");
  assertEquals(await storage.get("expire"), 4_600);
  assertEquals(emitted, [["update:authtoken", "new-access"]]);
});

test("tryRefreshToken keeps the current refresh token when it is not rotated", async () => {
  const { service, storage } = createService({
    accessToken: "new-access",
    tokenIssueTimeEpochSec: 2_000,
    durationUntilRefreshInSec: 1_800,
  });
  await storage.set("refreshToken", "existing-refresh");

  await service.tryRefreshToken();

  assertEquals(await storage.get("refreshToken"), "existing-refresh");
  assertEquals(await storage.get("expire"), 3_800);
});

test("tryRefreshToken deduplicates concurrent refresh attempts", async () => {
  const { service, storage, getRefreshCalls } = createService({
    accessToken: "new-access",
    refreshToken: "rotated-refresh",
    tokenIssueTimeEpochSec: 3_000,
    durationUntilRefreshInSec: 1_800,
  });
  await storage.set("refreshToken", "existing-refresh");

  await Promise.all([
    service.tryRefreshToken(),
    service.tryRefreshToken(),
    service.tryRefreshToken(),
  ]);

  assertEquals(getRefreshCalls(), 1);
});
