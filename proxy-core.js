const FORBIDDEN_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "accept-encoding",
  "range",
  "if-range",
]);

const PROXY_PARAMETERS = new Set([
  "url",
  "ref",
  "referer",
  "headers",
  "key",
  "playlist_key",
  "unwrap",
  "access",
]);

const FLIX_IMAGE_XOR_KEY = Uint8Array.from([
  157, 42, 241, 71, 179, 142, 92, 112,
  166, 25, 228, 59, 216, 98, 15, 197,
]);

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map((value) => value.trim()).filter(Boolean);
  const headers = {
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Authorization, Content-Type, If-Range, Range, X-Proxy-Token",
    "Access-Control-Expose-Headers": "Accept-Ranges, Content-Length, Content-Range, ETag, Last-Modified",
    "Vary": "Origin",
  };
  if (!allowed.length) headers["Access-Control-Allow-Origin"] = "*";
  else if (origin && (allowed.includes("*") || allowed.includes(origin))) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function jsonResponse(request, env, data, status, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(request, env),
      ...extraHeaders,
    },
  });
}

function isPrivateAddress(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || host === "localhost" || host === "metadata" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".home") || host.endsWith(".test") || host.endsWith(".invalid")) return true;
  if (host.includes(":")) {
    const value = host.split("%", 1)[0];
    if (value === "::" || value === "::1" || value.startsWith("fc") || value.startsWith("fd") || /^fe[89ab]/.test(value) || value.startsWith("ff") || value.startsWith("::ffff:")) return true;
    return false;
  }
  const octets = host.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = octets;
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0 && c === 0) || (a === 192 && b === 0 && c === 2) || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
}

export function assertSafeTarget(value, env = {}) {
  let target;
  try {
    target = value instanceof URL ? value : new URL(value);
  } catch {
    throw new Error("Invalid target URL");
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") throw new Error("Only HTTP and HTTPS targets are supported");
  if (target.username || target.password) throw new Error("Target URL credentials are not allowed");
  if (isPrivateAddress(target.hostname)) throw new Error("Private and local network targets are blocked");
  const allowlist = String(env.ALLOWED_HOSTS || "").split(",").map((host) => host.trim().toLowerCase()).filter(Boolean);
  if (allowlist.length && !allowlist.some((host) => target.hostname.toLowerCase() === host || target.hostname.toLowerCase().endsWith(`.${host}`))) {
    throw new Error("Target host is not allowed");
  }
  return target;
}

function parseHeaderParameter(value) {
  if (!value) return new Headers();
  if (value.length > 12_000) throw new Error("Upstream headers are too large");
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("Invalid upstream headers JSON");
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("Upstream headers must be an object");
  const headers = new Headers();
  const entries = Object.entries(parsed);
  if (entries.length > 48) throw new Error("Too many upstream headers");
  for (const [name, value] of entries) {
    const key = name.toLowerCase();
    if ((key === "referer" || key === "origin") && (typeof value === "string" || typeof value === "number")) {
      try {
        const webUrl = new URL(String(value));
        if (webUrl.protocol !== "http:" && webUrl.protocol !== "https:") continue;
        headers.set(name, key === "origin" ? webUrl.origin : webUrl.href);
      } catch {}
      continue;
    }
    if (FORBIDDEN_HEADERS.has(key) || key.startsWith("sec-") || key.startsWith("proxy-") || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name)) continue;
    if (typeof value !== "string" && typeof value !== "number") continue;
    headers.set(name, String(value));
  }
  return headers;
}

function parseRequestUrl(requestUrl, requestHeaders) {
  const url = new URL(requestUrl);
  let rawTarget = url.searchParams.get("url");
  let rawReferer = url.searchParams.get("ref") || url.searchParams.get("referer");
  if (!rawTarget) {
    const rawQuery = url.search.slice(1);
    if (/^https?:\/\//i.test(rawQuery)) rawTarget = rawQuery;
  }
  if (!rawTarget) throw new Error("Missing target URL");
  const pipe = rawTarget.indexOf("|");
  if (pipe >= 0) {
    const possibleReferer = rawTarget.slice(pipe + 1).trim();
    if (/^https?:\/\//i.test(possibleReferer)) {
      rawTarget = rawTarget.slice(0, pipe).trim();
      if (!rawReferer) rawReferer = possibleReferer;
    }
  }
  const target = assertSafeTarget(rawTarget);
  let referer = null;
  if (rawReferer) {
    referer = new URL(rawReferer);
    if (referer.protocol !== "http:" && referer.protocol !== "https:") throw new Error("Referer must use HTTP or HTTPS");
    referer = referer.href;
  }
  const upstreamHeaders = parseHeaderParameter(url.searchParams.get("headers"));
  const key = url.searchParams.get("playlist_key") || url.searchParams.get("key") || "";
  const unwrap = url.searchParams.get("unwrap") || "";
  const access = url.searchParams.get("access") || requestHeaders.get("X-Proxy-Token") || "";
  return { targetUrl: target.href, referer, upstreamHeaders, key, unwrap, access };
}

function buildContextParams(url, context) {
  if (context.referer) url.searchParams.set("ref", context.referer);
  if (context.upstreamHeaders && [...context.upstreamHeaders].length) {
    const headers = Object.fromEntries(context.upstreamHeaders.entries());
    url.searchParams.set("headers", JSON.stringify(headers));
  }
  if (context.key) url.searchParams.set("playlist_key", context.key);
  if (context.unwrap) url.searchParams.set("unwrap", context.unwrap);
  if (context.access) url.searchParams.set("access", context.access);
}

function buildProxyUrl(proxyBase, targetUrl, context, preserveTemplate = false) {
  const url = new URL(proxyBase);
  const templates = [];
  let target = targetUrl;
  if (preserveTemplate) target = target.replace(/\$[^$]+\$|\{\$[\w-]+\}/g, (token) => {
    const marker = `DASHVARIABLE${templates.length}X`;
    templates.push([marker, token]);
    return marker;
  });
  url.searchParams.set("url", target);
  buildContextParams(url, context);
  let value = url.href;
  for (const [marker, token] of templates) value = value.replaceAll(marker, token);
  return value;
}

function absoluteHttpUrl(reference, base) {
  try {
    const url = new URL(reference, base);
    if (url.protocol === "http:" || url.protocol === "https:") return url.href;
  } catch {}
  return null;
}

function rewriteM3u8(text, baseUrl, proxyBase, context) {
  return text.split(/\r?\n/).map((line) => {
    const trimmed = line.trim();
    if (!trimmed) return line;
    if (trimmed.startsWith("#")) {
      return line.replace(/\b(URI|SERVER-URI)=("([^"]*)"|'([^']*)')/gi, (full, name, quoted, doubleValue, singleValue) => {
        const value = doubleValue ?? singleValue ?? "";
        const absolute = absoluteHttpUrl(value, baseUrl);
        if (!absolute) return full;
        const proxied = buildProxyUrl(proxyBase, absolute, context);
        return `${name}=${quoted[0]}${proxied}${quoted[0]}`;
      });
    }
    const absolute = absoluteHttpUrl(trimmed, baseUrl);
    return absolute ? buildProxyUrl(proxyBase, absolute, context) : line;
  }).join("\n");
}

function xmlEscape(value) {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function xmlUnescape(value) {
  return value.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

const DASH_URL_ATTRIBUTES = new Set(["media", "initialization", "sourceurl", "index", "href", "manifesturl"]);

function rewriteMpd(text, baseUrl, proxyBase, context) {
  const tokens = text.match(/<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<[^>]+>|[^<]+/g) || [];
  const stack = [];
  const output = [];
  for (const token of tokens) {
    if (token.startsWith("</")) {
      stack.pop();
      output.push(token);
      continue;
    }
    if (!token.startsWith("<") || token.startsWith("<!--") || token.startsWith("<![CDATA[") || token.startsWith("<?") || token.startsWith("<!")) {
      const current = stack.at(-1);
      if (current?.name === "baseurl") {
        const match = token.match(/^(\s*)([\s\S]*?)(\s*)$/);
        const absolute = match?.[2] ? absoluteHttpUrl(xmlUnescape(match[2]), current.base) : null;
        if (absolute) {
          current.absolute = absolute;
          if (stack.length > 1) stack.at(-2).base = absolute;
          output.push(`${match[1]}${xmlEscape(buildProxyUrl(proxyBase, absolute, context))}${match[3]}`);
          continue;
        }
      }
      if ((current?.name === "location" || current?.name === "patchlocation") && token.trim()) {
        const match = token.match(/^(\s*)([\s\S]*?)(\s*)$/);
        const absolute = match?.[2] ? absoluteHttpUrl(xmlUnescape(match[2]), current.base) : null;
        if (absolute) {
          output.push(`${match[1]}${xmlEscape(buildProxyUrl(proxyBase, absolute, context))}${match[3]}`);
          continue;
        }
      }
      output.push(token);
      continue;
    }
    const tagMatch = token.match(/^<\s*([A-Za-z_:][\w:.-]*)/);
    if (!tagMatch) {
      output.push(token);
      continue;
    }
    const name = tagMatch[1].split(":").at(-1).toLowerCase();
    const parentBase = stack.at(-1)?.base || baseUrl;
    const rewritten = token.replace(/([A-Za-z_:][\w:.-]*)\s*=\s*("([^"]*)"|'([^']*)')/g, (full, attrName, quoted, doubleValue, singleValue) => {
      const attr = attrName.split(":").at(-1).toLowerCase();
      const value = doubleValue ?? singleValue ?? "";
      const shouldRewrite = DASH_URL_ATTRIBUTES.has(attr) || ((name === "utctiming" || name === "patchlocation") && attr === "value");
      if (!shouldRewrite || name === "baseurl") return full;
      const absolute = absoluteHttpUrl(xmlUnescape(value), parentBase);
      if (!absolute) return full;
      const proxied = buildProxyUrl(proxyBase, absolute, context, true);
      return `${attrName}=${quoted[0]}${xmlEscape(proxied)}${quoted[0]}`;
    });
    output.push(rewritten);
    if (!/\/\s*>$/.test(token)) stack.push({ name, base: parentBase });
  }
  return output.join("");
}

function decodeBase64(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function decryptManifest(text, key) {
  if (text.trimStart().startsWith("#EXTM3U")) return { text, decrypted: false };
  if (!key) return { text, decrypted: false };
  try {
    const keyBytes = decodeBase64(key);
    const payload = decodeBase64(text.trim());
    if (!keyBytes.length || !payload.length) return { text, decrypted: false };
    for (let index = 0; index < payload.length; index++) payload[index] ^= keyBytes[index % keyBytes.length];
    const decoded = new TextDecoder().decode(payload);
    if (decoded.trimStart().startsWith("#EXTM3U")) return { text: decoded, decrypted: true };
  } catch {}
  return { text, decrypted: false };
}

async function readLimitedText(response, limit) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > limit) {
      await reader.cancel();
      throw new Error("Upstream manifest exceeded the size limit");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

async function readLimitedBytes(response, limit) {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > limit) {
      await reader.cancel();
      throw new Error("Upstream segment exceeded the size limit");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function joinChunks(chunks, length) {
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function sniffManifest(response, limit) {
  if (!response.body) return null;
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  let done = false;
  let kind = null;
  while (length < limit && !kind) {
    const result = await reader.read();
    done = result.done;
    if (done) break;
    chunks.push(result.value);
    length += result.value.byteLength;
    const prefix = new TextDecoder().decode(joinChunks(chunks, length)).replace(/^\uFEFF/, "").trimStart();
    if (prefix.startsWith("#EXTM3U")) kind = "hls";
    else if (/<\s*(?:\w+:)?MPD\b/i.test(prefix)) kind = "dash";
  }
  return { reader, chunks, length, done, kind };
}

function replayStream(sniffed) {
  let index = 0;
  return new ReadableStream({
    async pull(controller) {
      if (index < sniffed.chunks.length) {
        controller.enqueue(sniffed.chunks[index++]);
        return;
      }
      if (sniffed.done) {
        controller.close();
        return;
      }
      try {
        const result = await sniffed.reader.read();
        if (result.done) controller.close();
        else controller.enqueue(result.value);
      } catch (error) {
        controller.error(error);
      }
    },
    cancel(reason) {
      return sniffed.reader.cancel(reason);
    },
  });
}

async function readSniffedText(sniffed, limit) {
  if (sniffed.length > limit) {
    await sniffed.reader.cancel();
    throw new Error("Upstream manifest exceeded the size limit");
  }
  const chunks = [...sniffed.chunks];
  let length = sniffed.length;
  while (!sniffed.done) {
    const result = await sniffed.reader.read();
    sniffed.done = result.done;
    if (result.done) break;
    length += result.value.byteLength;
    if (length > limit) {
      await sniffed.reader.cancel();
      throw new Error("Upstream manifest exceeded the size limit");
    }
    chunks.push(result.value);
  }
  return new TextDecoder().decode(joinChunks(chunks, length));
}

function unwrapFlixImage(bytes) {
  let offset = 0;
  if (bytes.length >= 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) offset = 12;
  else if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a) offset = 8;
  if (!offset) return null;
  let body = bytes.slice(offset);
  if (body[0] !== 0x47) {
    body = body.map((value, index) => value ^ FLIX_IMAGE_XOR_KEY[index % FLIX_IMAGE_XOR_KEY.length]);
  }
  return body[0] === 0x47 ? body : null;
}

function responseHeaders(request, env, upstream, contentType, options = {}) {
  const headers = new Headers(corsHeaders(request, env));
  headers.set("Content-Type", contentType || upstream.headers.get("Content-Type") || "application/octet-stream");
  const cache = options.noCache ? "no-store" : upstream.headers.get("Cache-Control");
  if (cache) headers.set("Cache-Control", cache);
  for (const name of ["Accept-Ranges", "Content-Range", "ETag", "Last-Modified", "Content-Disposition"]) {
    const value = upstream.headers.get(name);
    if (value) headers.set(name, value);
  }
  if (options.manifest) headers.set("X-Proxy-Manifest", options.manifest);
  if (options.unwrapped) headers.set("X-Proxy-Unwrapped", "flixcloud-hd2");
  return headers;
}

async function fetchWithTimeout(fetchImpl, url, method, headers, request, timeoutMs) {
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort(new Error("Upstream request timed out")), timeoutMs);
  const signal = request.signal ? AbortSignal.any([request.signal, timeoutController.signal]) : timeoutController.signal;
  try {
    return await fetchImpl(url, { method, headers, redirect: "manual", signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchFollowingRedirects({ targetUrl, method, headers, request, fetchImpl, fallbackFetch, validateTarget, env, timeoutMs, maxRedirects }) {
  let current = targetUrl;
  let currentHeaders = new Headers(headers);
  for (let redirects = 0; ; redirects++) {
    const parsed = assertSafeTarget(current, env);
    if (validateTarget) await validateTarget(parsed, env);
    let response;
    let usedFallback = false;
    try {
      response = await fetchWithTimeout(fetchImpl, current, method, currentHeaders, request, timeoutMs);
    } catch (error) {
      if (!fallbackFetch || request.signal?.aborted) throw error;
      response = await fetchWithTimeout(fallbackFetch, current, method, currentHeaders, request, timeoutMs);
      if (!response) throw error;
      usedFallback = true;
    }
    if (response.status === 403 && fallbackFetch && !usedFallback) {
      const fallback = await fetchWithTimeout(fallbackFetch, current, method, currentHeaders, request, timeoutMs).catch(() => null);
      if (fallback) {
        await response.body?.cancel().catch(() => {});
        response = fallback;
      }
    }
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.get("Location");
    if (!location) return response;
    if (redirects >= maxRedirects) {
      await response.body?.cancel().catch(() => {});
      throw new Error("Too many upstream redirects");
    }
    const next = new URL(location, current);
    assertSafeTarget(next, env);
    if (new URL(current).origin !== next.origin) {
      currentHeaders.delete("Authorization");
      currentHeaders.delete("Cookie");
    }
    await response.body?.cancel().catch(() => {});
    current = next.href;
  }
}

export function createProxyHandler(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const fallbackFetch = options.fallbackFetch || null;
  const validateTarget = options.validateTarget || null;
  const timeoutMs = options.timeoutMs || 20_000;
  const maxRedirects = options.maxRedirects || 8;
  const maxManifestBytes = options.maxManifestBytes || 2 * 1024 * 1024;
  const maxSegmentBytes = options.maxSegmentBytes || 48 * 1024 * 1024;

  return async function handleProxyRequest(request, env = {}) {
    const requestUrl = new URL(request.url);
    const headers = corsHeaders(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (requestUrl.pathname === "/health" || (requestUrl.pathname === "/" && !requestUrl.searchParams.has("url"))) {
      return new Response(JSON.stringify({ status: "ok" }), { status: 200, headers: { ...headers, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
    }
    if (request.method !== "GET" && request.method !== "HEAD") return jsonResponse(request, env, { error: "Method not allowed" }, 405, { Allow: "GET, HEAD, OPTIONS" });
    let parsed;
    try {
      parsed = parseRequestUrl(request.url, request.headers);
      const expectedToken = String(env.PROXY_TOKEN || "");
      if (expectedToken && parsed.access !== expectedToken) return jsonResponse(request, env, { error: "Unauthorized" }, 401);
      if (validateTarget) await validateTarget(new URL(parsed.targetUrl), env);
    } catch (error) {
      const message = String(error?.message || error);
      const status = /Missing target URL/.test(message) ? 400 : /Private|local network|not allowed|credentials/.test(message) ? 403 : 400;
      return jsonResponse(request, env, { error: message }, status);
    }

    let referer = parsed.referer || `${new URL(parsed.targetUrl).origin}/`;
    const headerReferer = parsed.upstreamHeaders.get("Referer");
    if (!parsed.referer && headerReferer) {
      try {
        const candidate = new URL(headerReferer);
        if (candidate.protocol === "http:" || candidate.protocol === "https:") referer = candidate.href;
      } catch {}
    }
    const refererOrigin = new URL(referer).origin;
    const upstreamHeaders = new Headers({
      Accept: request.headers.get("Accept") || "*/*",
      "Accept-Language": request.headers.get("Accept-Language") || "en-US,en;q=0.9",
      Referer: referer,
      Origin: refererOrigin,
    });
    const userAgent = request.headers.get("User-Agent") || env.PROXY_USER_AGENT;
    if (userAgent) upstreamHeaders.set("User-Agent", userAgent);
    for (const [name, value] of parsed.upstreamHeaders) upstreamHeaders.set(name, value);
    const range = request.headers.get("Range");
    const ifRange = request.headers.get("If-Range");
    if (range && parsed.unwrap !== "flixcloud-hd2") upstreamHeaders.set("Range", range);
    if (ifRange && parsed.unwrap !== "flixcloud-hd2") upstreamHeaders.set("If-Range", ifRange);
    const proxyPath = options.proxyPath || requestUrl.pathname;
    const proxyBase = `${requestUrl.origin}${proxyPath}`;
    let upstream;
    try {
      upstream = await fetchFollowingRedirects({
        targetUrl: parsed.targetUrl,
        method: request.method,
        headers: upstreamHeaders,
        request,
        fetchImpl,
        fallbackFetch,
        validateTarget,
        env,
        timeoutMs,
        maxRedirects,
      });
    } catch (error) {
      const status = request.signal?.aborted ? 499 : /Private|local network|not allowed|credentials/.test(String(error?.message)) ? 403 : 502;
      return jsonResponse(request, env, { error: status === 502 ? "Upstream request failed" : String(error.message || error) }, status);
    }

    if (request.method === "HEAD") {
      return new Response(null, { status: upstream.status, headers: responseHeaders(request, env, upstream) });
    }

    const finalUrl = upstream.url || parsed.targetUrl;
    const childContext = { ...parsed, upstreamHeaders: new Headers(parsed.upstreamHeaders) };
    if (new URL(finalUrl).origin !== new URL(parsed.targetUrl).origin) {
      childContext.upstreamHeaders.delete("Authorization");
      childContext.upstreamHeaders.delete("Cookie");
    }
    const type = (upstream.headers.get("Content-Type") || "").toLowerCase();
    const pathname = new URL(finalUrl).pathname.toLowerCase();
    let isHls = pathname.endsWith(".m3u8") || type.includes("mpegurl") || type.includes("vnd.apple.mpegurl");
    let isDash = pathname.endsWith(".mpd") || type.includes("dash+xml");
    const isFlixImage = parsed.unwrap === "flixcloud-hd2" && (pathname.endsWith(".png") || pathname.endsWith(".webp") || type.includes("image/png") || type.includes("image/webp"));

    let sniffed = null;
    if (!isHls && !isDash && !isFlixImage && !type.startsWith("video/") && !type.startsWith("audio/") && !type.includes("image/png") && !type.includes("image/webp")) {
      try {
        sniffed = await sniffManifest(upstream, 16 * 1024);
      } catch (error) {
        return jsonResponse(request, env, { error: String(error.message || error) }, 502);
      }
      isHls = sniffed?.kind === "hls";
      isDash = sniffed?.kind === "dash";
      if (!isHls && !isDash) {
        return new Response(sniffed ? replayStream(sniffed) : upstream.body, {
          status: upstream.status,
          headers: responseHeaders(request, env, upstream),
        });
      }
    }

    if (isHls || isDash) {
      let body;
      try {
        body = sniffed ? await readSniffedText(sniffed, maxManifestBytes) : await readLimitedText(upstream, maxManifestBytes);
      } catch (error) {
        return jsonResponse(request, env, { error: String(error.message || error) }, 502);
      }
      let manifest = body;
      let decrypted = false;
      if (isHls) ({ text: manifest, decrypted } = decryptManifest(body, parsed.key));
      const isRecognized = isHls ? manifest.trimStart().startsWith("#EXTM3U") : /<\s*(?:\w+:)?MPD\b/i.test(manifest);
      if (!isRecognized) {
        return new Response(body, {
          status: upstream.status,
          headers: responseHeaders(request, env, upstream, type || (isHls ? "application/octet-stream" : "application/octet-stream"), { noCache: true, manifest: parsed.key ? "key-not-matched" : "opaque" }),
        });
      }
      const rewritten = isHls ? rewriteM3u8(manifest, finalUrl, proxyBase, childContext) : rewriteMpd(manifest, finalUrl, proxyBase, childContext);
      return new Response(rewritten, {
        status: upstream.status,
        headers: responseHeaders(request, env, upstream, isHls ? "application/vnd.apple.mpegurl" : "application/dash+xml", {
          noCache: true,
          manifest: decrypted ? "decrypted-and-rewritten" : "rewritten",
        }),
      });
    }

    if (isFlixImage && upstream.ok) {
      let wrapped;
      try {
        wrapped = await readLimitedBytes(upstream, maxSegmentBytes);
      } catch (error) {
        return jsonResponse(request, env, { error: String(error.message || error) }, 502);
      }
      const unwrapped = unwrapFlixImage(wrapped);
      if (unwrapped) {
        let status = upstream.status;
        let body = unwrapped;
        let contentRange = null;
        if (range) {
          const match = range.match(/^bytes=(\d*)-(\d*)$/);
          if (!match || (!match[1] && !match[2])) return jsonResponse(request, env, { error: "Invalid byte range" }, 416);
          const start = match[1] ? Number(match[1]) : Math.max(0, body.length - Number(match[2]));
          const end = match[2] ? Math.min(body.length - 1, Number(match[2])) : body.length - 1;
          if (start >= body.length || end < start) return new Response(null, { status: 416, headers: responseHeaders(request, env, upstream, "video/mp2t", { unwrapped: true }) });
          body = body.slice(start, end + 1);
          status = 206;
          contentRange = `bytes ${start}-${end}/${unwrapped.length}`;
        }
        const outputHeaders = responseHeaders(request, env, upstream, "video/mp2t", { unwrapped: true });
        outputHeaders.set("Accept-Ranges", "bytes");
        if (contentRange) outputHeaders.set("Content-Range", contentRange);
        return new Response(body, { status, headers: outputHeaders });
      }
      return new Response(wrapped, {
        status: upstream.status,
        headers: responseHeaders(request, env, upstream),
      });
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders(request, env, upstream),
    });
  };
}

export const handleProxyRequest = createProxyHandler();
