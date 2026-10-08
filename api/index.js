import { createProxyHandler } from "../proxy-core.js";

export const config = { runtime: "edge" };

const handleProxyRequest = createProxyHandler({ proxyPath: "/api/proxy" });

export default function handler(request) {
  const env = typeof process === "undefined" ? {} : process.env;
  return handleProxyRequest(request, env);
}
