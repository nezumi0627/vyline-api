import { describe, expect, test } from "bun:test";
import { LegyEncryptedTransport } from "./legy.ts";

describe("encrypted login follow-up requests", () => {
  test("does not reuse a connection with another account's encryption key", async () => {
    const keysByConnection = new Map<number, string>();
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request, server) {
        const port = server.requestIP(request)!.port;
        const key = request.headers.get("x-lcs")!;
        const previous = keysByConnection.get(port);
        keysByConnection.set(port, key);
        return new Response(null, { status: previous && previous !== key ? 409 : 200 });
      },
    });

    try {
      const statuses: number[] = [];
      for (let account = 0; account < 3; account++) {
        const response = await new LegyEncryptedTransport(server.url.href).fetch(
          new Request("https://example.invalid/S4", {
            method: "POST", body: new Uint8Array([1]),
          }),
          (request) => fetch(request),
          { application: "IOSIPAD", userAgent: "test" },
        );
        statuses.push(response.status);
      }
      expect(statuses).toEqual([200, 200, 200]);
      expect(keysByConnection.size).toBe(3);
    } finally {
      server.stop(true);
    }
  });

  test("preserves cancellation independently for each account", async () => {
    const pending: Request[] = [];
    const fetcher = async (request: Request) => {
      pending.push(request);
      return new Response(null, { status: 200 });
    };
    const controllers = [new AbortController(), new AbortController()];
    for (const controller of controllers) {
      await new LegyEncryptedTransport().fetch(
        new Request("https://example.invalid/S4", {
          method: "POST",
          body: new Uint8Array([1, 2, 3]),
          signal: controller.signal,
        }),
        fetcher,
        { application: "IOSIPAD", userAgent: "test" },
      );
    }

    controllers[1]!.abort();
    expect(pending[0]!.signal.aborted).toBe(false);
    expect(pending[1]!.signal.aborted).toBe(true);
  });

  test("forwards the timeout reason so a stalled profile request can terminate", async () => {
    const controller = new AbortController();
    const timeout = new DOMException("profile request timed out", "TimeoutError");
    controller.abort(timeout);

    await new LegyEncryptedTransport().fetch(
      new Request("https://example.invalid/S4", {
        method: "POST", body: new Uint8Array([1]), signal: controller.signal,
      }),
      async (request) => {
        expect(request.signal.aborted).toBe(true);
        expect(request.signal.reason).toBe(timeout);
        return new Response(null, { status: 200 });
      },
      { application: "IOSIPAD", userAgent: "test" },
    );
  });
});
