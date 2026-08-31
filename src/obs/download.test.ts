import { expect, test } from "bun:test";
import { downloadObsMessageBytes, downloadObsMessageResponse } from "./download.js";

test("returns the OBS response body without eagerly reading it", async () => {
  let pulled = false;
  let requestUrl = "";
  let requestInit: RequestInit | undefined;
  const controller = new AbortController();
  const response = await downloadObsMessageResponse(
    {
      authToken: "token",
      systemType: "TEST",
      prefix: "https://obs.example/",
      fetch: async (url, init) => {
        requestUrl = url;
        requestInit = init;
        return new Response(
          new ReadableStream<Uint8Array>({
            pull(stream) {
              pulled = true;
              stream.enqueue(Uint8Array.from([1, 2, 3]));
              stream.close();
            },
          }),
          { status: 200, headers: { "Content-Type": "video/mp4" } },
        );
      },
    },
    "message/id",
    { signal: controller.signal },
  );

  expect(requestUrl).toBe("https://obs.example/r/talk/m/message%2Fid");
  expect(new Headers(requestInit?.headers).get("x-line-access")).toBe("token");
  expect(requestInit?.signal).toBe(controller.signal);
  expect(response.bodyUsed).toBe(false);
  expect(new Uint8Array(await response.arrayBuffer())).toEqual(Uint8Array.from([1, 2, 3]));
  expect(response.bodyUsed).toBe(true);
  expect(pulled).toBe(true);
});

test("keeps the compatibility byte API and rejects non-success responses", async () => {
  const deps = {
    authToken: "token",
    systemType: "TEST",
    fetch: async () =>
      new Response(Uint8Array.from([4, 5]), {
        status: 200,
        headers: { "Content-Type": "image/png" },
      }),
  };
  await expect(downloadObsMessageBytes(deps, "123")).resolves.toEqual({
    bytes: Uint8Array.from([4, 5]),
    contentType: "image/png",
  });
  await expect(
    downloadObsMessageResponse({ ...deps, fetch: async () => new Response(null, { status: 404 }) }, "missing"),
  ).rejects.toThrow("OBS download failed: HTTP 404");
});
