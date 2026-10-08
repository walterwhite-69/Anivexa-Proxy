import { handleProxyRequest } from "./proxy-core.js";

export default {
  fetch(request, env) {
    return handleProxyRequest(request, env || {});
  },
};
