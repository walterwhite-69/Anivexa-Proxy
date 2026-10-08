import assert from "node:assert/strict";
import test from "node:test";
import { assertSafeTarget, createProxyHandler } from "../proxy-core.js";

function proxyUrl(target, values = {}) {
  const url = new URL("https://proxy.example/proxy");
  url.searchParams.set("url", target);
  for (const [name, value] of Object.entries(values)) url.searchParams.set(name, value);
  return url.href;
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

test("keeps percent escapes inside signed upstream URLs intact", async () => {
  let requested;
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async (url) => {
      requested = url;
      return new Response("ok", { headers: { "Content-Type": "text/plain" } });
    },
  });
  const target = "https://cdn.example/a%2Fb/master.m3u8?signature=x%2Fy%3D";
  const response = await handler(new Request(proxyUrl(target)));
  assert.equal(response.status, 200);
  assert.equal(requested, target);
});

test("derives Origin from a stream Referer without inventing fetch metadata", async () => {
  let received;
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async (_url, options) => {
      received = {
        origin: options.headers.get("Origin"),
        referer: options.headers.get("Referer"),
        fetchMetadata: ["Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site"].map(name => options.headers.get(name)),
      };
      return new Response("ok");
    },
  });
  const referer = "https://krussdomi.com/";
  const response = await handler(new Request(proxyUrl("https://hls.example/master.m3u8", {
    headers: JSON.stringify({ Referer: referer }),
  })));
  assert.equal(response.status, 200);
  assert.deepEqual(received, {
    origin: "https://krussdomi.com",
    referer,
    fetchMetadata: [null, null, null],
  });
});

test("rewrites HLS variants, keys, maps, and segments while preserving child context", async () => {
  const playlist = [
    "#EXTM3U",
    '#EXT-X-KEY:METHOD=AES-128,URI="keys/key.bin?sig=a%2Fb"',
    '#EXT-X-MAP:URI="init.mp4"',
    "#EXTINF:5,",
    "segments/one.ts?token=x%2Fy",
    "#EXT-X-ENDLIST",
  ].join("\n");
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async () => new Response(playlist, { headers: { "Content-Type": "text/plain" } }),
  });
  const response = await handler(new Request(proxyUrl("https://cdn.example/video/master.m3u8", {
    ref: "https://player.example/watch/episode",
    headers: JSON.stringify({ Authorization: "Bearer test-token" }),
  })));
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Proxy-Manifest"), "rewritten");
  assert.match(body, /^#EXTM3U/);
  const keyUrl = body.match(/URI="([^"]+)"/)[1];
  const keyRequest = new URL(keyUrl);
  assert.equal(keyRequest.searchParams.get("url"), "https://cdn.example/video/keys/key.bin?sig=a%2Fb");
  assert.equal(keyRequest.searchParams.get("ref"), "https://player.example/watch/episode");
  assert.equal(JSON.parse(keyRequest.searchParams.get("headers")).authorization, "Bearer test-token");
  const segmentUrl = body.split("\n").find((line) => line && !line.startsWith("#"));
  assert.equal(new URL(segmentUrl).searchParams.get("url"), "https://cdn.example/video/segments/one.ts?token=x%2Fy");
});

test("decrypts a keyed Base64-XOR HLS manifest before rewriting", async () => {
  const key = Uint8Array.from([1, 17, 33, 65]);
  const plain = new TextEncoder().encode("#EXTM3U\nsegment.ts\n");
  const encrypted = plain.map((value, index) => value ^ key[index % key.length]);
  const payload = toBase64(encrypted);
  const keyValue = toBase64(key);
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async () => new Response(payload, { headers: { "Content-Type": "text/plain" } }),
  });
  const response = await handler(new Request(proxyUrl("https://cdn.example/master.m3u8", { playlist_key: keyValue })));
  assert.equal(response.headers.get("X-Proxy-Manifest"), "decrypted-and-rewritten");
  assert.match(await response.text(), /^#EXTM3U/);
});

test("sniffs and rewrites extensionless HLS mislabeled as an image", async () => {
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async () => new Response("#EXTM3U\nsegment.ts\n", { headers: { "Content-Type": "image/jpeg" } }),
  });
  const response = await handler(new Request(proxyUrl("https://cdn.example/cdn/asset?id=token")));
  const body = await response.text();
  assert.equal(response.headers.get("X-Proxy-Manifest"), "rewritten");
  assert.equal(new URL(body.split("\n")[1]).searchParams.get("url"), "https://cdn.example/cdn/segment.ts");
});

test("replays sniffed binary bodies without modifying their bytes", async () => {
  const bytes = Uint8Array.from([0xff, 0xd8, 0x00, 0xff, 0xd9, 0x7f]);
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async () => new Response(bytes, { headers: { "Content-Type": "image/jpeg" } }),
  });
  const response = await handler(new Request(proxyUrl("https://cdn.example/image?id=asset")));
  assert.deepEqual([...new Uint8Array(await response.arrayBuffer())], [...bytes]);
});

test("rewrites DASH BaseURL paths and preserves URL templates", async () => {
  const mpd = '<MPD><Period><BaseURL>segments/</BaseURL><AdaptationSet><Representation><SegmentTemplate initialization="init-$RepresentationID$.mp4" media="chunk-$Number%05d$.m4s"/></Representation></AdaptationSet></Period></MPD>';
  const calls = [];
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async (url) => {
      calls.push(url);
      if (url.endsWith("manifest.mpd")) return new Response(mpd, { headers: { "Content-Type": "application/dash+xml" } });
      return new Response("segment", { headers: { "Content-Type": "video/mp4" } });
    },
  });
  const response = await handler(new Request(proxyUrl("https://cdn.example/vod/manifest.mpd", { ref: "https://player.example/" })));
  const body = await response.text();
  assert.equal(response.headers.get("X-Proxy-Manifest"), "rewritten");
  const base = body.match(/<BaseURL>([^<]+)<\/BaseURL>/)[1].replace(/&amp;/g, "&");
  assert.equal(new URL(base).searchParams.get("url"), "https://cdn.example/vod/segments/");
  const template = body.match(/media="([^"]+)"/)[1].replace(/&amp;/g, "&");
  assert.match(template, /\$Number%05d\$/);
  const child = new URL(template.replace("$Number%05d$", "8"));
  const childResponse = await handler(new Request(child));
  assert.equal(childResponse.status, 200);
  assert.equal(calls[1], "https://cdn.example/vod/segments/chunk-8.m4s");
});

test("forwards byte ranges and preserves partial-response metadata", async () => {
  let receivedRange;
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async (_url, options) => {
      receivedRange = options.headers.get("Range");
      return new Response(Uint8Array.from([10, 11, 12]), {
        status: 206,
        headers: { "Content-Type": "video/mp4", "Content-Range": "bytes 0-2/30", "Accept-Ranges": "bytes" },
      });
    },
  });
  const request = new Request(proxyUrl("https://cdn.example/video.mp4"), { headers: { Range: "bytes=0-2" } });
  const response = await handler(request);
  assert.equal(receivedRange, "bytes=0-2");
  assert.equal(response.status, 206);
  assert.equal(response.headers.get("Content-Range"), "bytes 0-2/30");
  assert.deepEqual([...new Uint8Array(await response.arrayBuffer())], [10, 11, 12]);
});

test("unwraps HD-2 image-wrapped media and serves local byte ranges", async () => {
  const image = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x47, 0x01, 0x02]);
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async () => new Response(image, { headers: { "Content-Type": "image/png" } }),
  });
  const request = new Request(proxyUrl("https://cdn.example/segment.png", { unwrap: "flixcloud-hd2" }), { headers: { Range: "bytes=0-0" } });
  const response = await handler(request);
  assert.equal(response.status, 206);
  assert.equal(response.headers.get("Content-Type"), "video/mp2t");
  assert.equal(response.headers.get("X-Proxy-Unwrapped"), "flixcloud-hd2");
  assert.deepEqual([...new Uint8Array(await response.arrayBuffer())], [0x47]);
});

test("rejects local targets and redirects to private addresses", async () => {
  assert.throws(() => assertSafeTarget("http://127.0.0.1/"), /Private and local/);
  let calls = 0;
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async () => {
      calls++;
      return new Response(null, { status: 302, headers: { Location: "http://127.0.0.1/admin" } });
    },
  });
  const response = await handler(new Request(proxyUrl("https://cdn.example/redirect")));
  assert.equal(response.status, 403);
  assert.equal(calls, 1);
});

test("uses Wreq once after an upstream 403", async () => {
  let fallbacks = 0;
  const handler = createProxyHandler({
    validateTarget: async () => {},
    fetchImpl: async () => new Response("blocked", { status: 403 }),
    fallbackFetch: async () => {
      fallbacks++;
      return new Response("ok", { status: 200 });
    },
  });
  const response = await handler(new Request(proxyUrl("https://cdn.example/file.mp4")));
  assert.equal(response.status, 200);
  assert.equal(fallbacks, 1);
});

test("supports preflight and rejects unsupported methods", async () => {
  const handler = createProxyHandler();
  const preflight = await handler(new Request("https://proxy.example/proxy", { method: "OPTIONS" }));
  assert.equal(preflight.status, 204);
  const post = await handler(new Request("https://proxy.example/proxy", { method: "POST" }));
  assert.equal(post.status, 405);
});
