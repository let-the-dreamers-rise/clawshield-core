/**
 * Response headers for the public site, applied by Vercel (scripts/build-web.ts) and by the
 * local preview (scripts/preview-web.ts) alike.
 *
 * The page runs one same-origin script and loads nothing from anywhere else. Its only
 * cross-origin traffic is to the Solana RPC endpoint the visitor chooses, which is why
 * connect-src admits any HTTPS origin (and a local validator) rather than one fixed host.
 */

export const SITE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join("; ");

export const SITE_HEADERS: Readonly<Record<string, string>> = {
  "content-security-policy": SITE_CSP,
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
};
