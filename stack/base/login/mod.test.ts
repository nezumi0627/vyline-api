import { assert, assertEquals, assertRejects } from "@vyline/protocol/stack/assert";
import type { BaseClient } from "../core/mod.js";
import { test } from "bun:test";
import { Login, random6DigitPin, registrationAuthEndpoint } from "./mod.ts";

test("registration auth endpoint uses v4 for Android devices", () => {
  assertEquals(registrationAuthEndpoint("ANDROID"), "/api/v4p/rs");
  assertEquals(registrationAuthEndpoint("ANDROIDSECONDARY"), "/api/v4p/rs");
});

test("registration auth endpoint keeps v3 for existing desktop and iOS logins", () => {
  assertEquals(registrationAuthEndpoint("DESKTOPWIN"), "/api/v3p/rs");
  assertEquals(registrationAuthEndpoint("DESKTOPMAC"), "/api/v3p/rs");
  assertEquals(registrationAuthEndpoint("IOS"), "/api/v3p/rs");
  assertEquals(registrationAuthEndpoint("IOSIPAD"), "/api/v3p/rs");
});

test("email login default PINs are random six-digit values and never logged", async () => {
  const pins = Array.from({ length: 32 }, () => random6DigitPin());
  const logs: unknown[] = [];
  const client = {
    log(_type: string, data: unknown) {
      logs.push(data);
    },
  } as unknown as BaseClient;
  const login = new Login(client);
  login.getRSAKeyInfo = async () => {
    throw new Error("stop after observing PIN");
  };

  await assertRejects(
    () => login.requestEmailLogin("user@example.com", "password", "123456", false),
    Error,
    "stop after observing PIN",
  );

  for (const pin of pins) assert(/^\d{6}$/.test(pin));
  assert(new Set(pins).size > 1);
  const encoded = JSON.stringify(logs);
  assert(!encoded.includes("123456"));
  assert(!encoded.includes("user@example.com"));
  assert(!encoded.includes("password"));
});
