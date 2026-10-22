const backend = process.env.BACKEND_INTERNAL_URL || "http://localhost:8000";
const dev = process.env.NODE_ENV !== "production";

const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${dev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "worker-src 'self' blob:", // MapLibre renders tiles/geometry in a blob: web worker
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

/** @type {import('next').NextConfig} */
export default {
  output: "standalone",
  poweredByHeader: false,
  compress: false, // gzip would buffer Server-Sent Events (the live AI hunt view) until the response ends
  // AI hunts (deep mode) have no time limit; the default proxy timeout (~30s) turned finished runs into a 500. A stopped stream does not
  // lose the run (it is saved server-side), but the live view would end, so the proxy waits up to a week.
  experimental: { proxyTimeout: 604_800_000 },
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${backend}/api/:path*` },
      { source: "/backend-health/:path*", destination: `${backend}/:path*` },
    ];
  },
  async headers() {
    return [{
      source: "/:path*",
      headers: [
        { key: "Content-Security-Policy", value: csp },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Referrer-Policy", value: "no-referrer" },
        { key: "Permissions-Policy", value: "geolocation=(), microphone=(), camera=()" },
      ],
    }];
  },
};
