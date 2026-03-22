// Stub for undici's ProxyAgent, which @actions/http-client imports but only
// uses when a proxy is configured. Avoids bundling ~500KB of undici.
export const ProxyAgent = undefined;
