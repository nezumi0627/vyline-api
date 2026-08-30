import { describe, expect, test } from "bun:test";
import { BaseClient } from "../core/mod.ts";
import { Protocols, Thrift } from "../thrift/mod.ts";

describe("account RPC transport", () => {
  test("fetches profiles for three legacy-token accounts without sharing their connections", async () => {
    const tokensByConnection = new Map<number, string>();
    const wire = new Thrift();
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(request, server) {
        await request.arrayBuffer();
        const port = server.requestIP(request)!.port;
        const token = request.headers.get("x-line-access")!;
        const previous = tokensByConnection.get(port);
        tokensByConnection.set(port, token);
        if (previous && previous !== token) return new Response(null, { status: 409 });
        const body = wire.writeThrift(
          [[12, 0, [[11, 1, `profile-${token}`]]]],
          "getProfile",
          Protocols[4],
        );
        return new Response(new Uint8Array(body), {
          headers: { "content-type": "application/x-thrift" },
        });
      },
    });

    try {
      for (let account = 1; account <= 3; account++) {
        const client = new BaseClient({
          device: "IOSIPAD",
          fetch: (request) => fetch(new Request(server.url.href, request)),
        });
        client.authToken = `opaque-account-${account}`;
        const profile = await client.talk.getProfile();
        expect(profile?.mid).toBe(`profile-opaque-account-${account}`);
      }
      expect(tokensByConnection.size).toBe(3);
    } finally {
      server.stop(true);
    }
  });

  test("does not add HTTP/1 connection headers to shared headers used by HTTP/2 push", () => {
    const client = new BaseClient({ device: "IOSIPAD" });
    expect(client.request.getHeader()).not.toHaveProperty("connection");
  });
});
