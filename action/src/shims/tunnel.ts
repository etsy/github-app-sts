// Stub for tunnel, which @actions/http-client imports but only uses when a
// proxy is configured. Avoids bundling a CJS module that breaks ESM output.
export const httpOverHttp = undefined;
export const httpsOverHttp = undefined;
export const httpOverHttps = undefined;
export const httpsOverHttps = undefined;
