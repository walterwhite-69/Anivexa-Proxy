import http from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createProxyHandler } from "./proxy-core.js";
import { validatePublicTarget } from "./node-safety.js";
import { fetchWithWreq } from "./wreq-fallback.js";

const PORT = Number(process.env.PORT) || 8080;
const handleProxyRequest = createProxyHandler({
  validateTarget: validatePublicTarget,
  fallbackFetch: fetchWithWreq,
});

const server = http.createServer(async (req, res) => {
  const host = req.headers.host || `127.0.0.1:${PORT}`;
  const forwardedProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  const protocol = forwardedProto === "https" ? "https" : "http";
  const controller = new AbortController();
  req.on("aborted", () => controller.abort());
  res.on("close", () => {
    if (!res.writableEnded) controller.abort();
  });
  try {
    const request = new Request(`${protocol}://${host}${req.url}`, {
      method: req.method,
      headers: req.headers,
      signal: controller.signal,
    });
    const response = await handleProxyRequest(request, process.env);
    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    if (!response.body) return res.end();
    await pipeline(Readable.fromWeb(response.body), res);
  } catch (error) {
    if (res.headersSent) return res.destroy(error);
    res.writeHead(500, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
    res.end(JSON.stringify({ error: "Proxy request failed" }));
  }
});

server.listen(PORT, () => {
  process.stdout.write(`Anivexa-Proxy listening on ${PORT}\n`);
});
