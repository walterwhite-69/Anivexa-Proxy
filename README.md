# Anivexa-Proxy

A streaming proxy for HLS, DASH, MP4, and media segments. The Node, Vercel, and Cloudflare Worker entry points share one implementation; it does not keep a CDN/provider hostname list.

## Run locally

Node.js 20 or newer:

```sh
npm install
npm start
```

The server listens on port `8080` by default. Set `PORT` to change it. The proxy endpoint is `/proxy`; `/health` returns a health check.

## Request

Pass the target as a URL-encoded `url` parameter. Include `ref` when the upstream requires a page referer.

```js
const proxy = new URL("https://proxy.example/proxy");
proxy.searchParams.set("url", stream.url);
proxy.searchParams.set("ref", stream.referer || "https://player.example/");

if (stream.headers) {
  proxy.searchParams.set("headers", JSON.stringify(stream.headers));
}

if (stream.playlist_key || stream.key) {
  proxy.searchParams.set("playlist_key", stream.playlist_key || stream.key);
}

if (stream.server === "HD-2") {
  proxy.searchParams.set("unwrap", "flixcloud-hd2");
}
```

The proxy rewrites HLS variants, segments, encryption keys, maps, and subtitle playlists. It supports DASH `BaseURL` and media-template references, forwards MP4 byte ranges, preserves upstream status codes, and streams binary bodies without buffering them. URLs returned in an API `headers` object can be supplied through the `headers` parameter.

For ReAnime FlixCloud, encrypted manifests can be decoded when the API's `playlist_key` or `key` is passed. HD-2 image-wrapped segments need `unwrap=flixcloud-hd2`; the mode is propagated to child segment URLs. DRM-protected streams and opaque encrypted manifests without their required key are not made playable by the proxy.

## Deployment

- Node or Render: `node node-server.js`
- Cloudflare Workers: `npx wrangler deploy proxy.js --name anivexa-proxy`
- Vercel: deploy the included `api/index.js` and `vercel.json`

## Configuration

| Variable | Effect |
|---|---|
| `PORT` | Node server port; default `8080` |
| `PROXY_TOKEN` | Require the matching `access` query parameter or `X-Proxy-Token` header |
| `ALLOWED_HOSTS` | Optional comma-separated host allowlist; entries also match subdomains |
| `ALLOWED_ORIGINS` | Optional comma-separated browser-origin allowlist |
| `PROXY_USER_AGENT` | Default upstream user agent when the caller supplies none |

Private, loopback, link-local, and local-name targets are rejected. The Node runtime additionally checks DNS results and every redirect. If deployed publicly, configure `PROXY_TOKEN` and/or `ALLOWED_HOSTS`; otherwise this is an unauthenticated relay for public internet hosts. Do not put long-lived secrets in query strings on services whose access logs retain full URLs.

Node retries an upstream `403` or network failure with `wreq-js` when available. Edge deployments use their platform's standard `fetch` implementation.

## Test

```sh
npm test
```
