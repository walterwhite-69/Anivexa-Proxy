import { lookup } from "node:dns/promises";
import { assertSafeTarget } from "./proxy-core.js";

const addressCache = new Map();
const CACHE_TTL = 60_000;

export async function validatePublicTarget(target, env = {}) {
  const url = assertSafeTarget(target, env);
  const hostname = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":")) return;
  const cached = addressCache.get(hostname);
  let addresses;
  if (cached && cached.expiresAt > Date.now()) addresses = cached.addresses;
  else {
    const resolved = await lookup(hostname, { all: true, verbatim: true });
    addresses = resolved.map((item) => item.address);
    if (!addresses.length) throw new Error("Target host did not resolve");
    addressCache.set(hostname, { addresses, expiresAt: Date.now() + CACHE_TTL });
  }
  for (const address of addresses) {
    const wrapped = address.includes(":") ? `http://[${address}]/` : `http://${address}/`;
    assertSafeTarget(wrapped, env);
  }
}
