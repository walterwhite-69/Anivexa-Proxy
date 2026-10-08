let sessionPromise;

export async function fetchWithWreq(url, options = {}) {
  let createSession;
  try {
    ({ createSession } = await import("wreq-js"));
  } catch {
    return null;
  }
  sessionPromise ||= createSession({ browser: "chrome_149", os: "windows" }).catch((error) => {
    sessionPromise = null;
    throw error;
  });
  const session = await sessionPromise;
  return session.fetch(url, {
    method: options.method || "GET",
    headers: Object.fromEntries(new Headers(options.headers).entries()),
    redirect: "manual",
    signal: options.signal,
  });
}
