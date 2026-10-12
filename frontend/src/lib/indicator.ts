/** Client-side classification of a pasted indicator. Used only to choose which search to offer; the server re-validates everything. */
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6 = /^(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}$/;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;

export type IndicatorKind = "ip" | "sha256" | "sha1" | "md5" | "domain" | null;
export function detectType(raw: string): IndicatorKind {
  const v = raw.trim();
  if (IPV4.test(v) || IPV6.test(v)) return "ip";
  if (/^[a-f0-9]{64}$/i.test(v)) return "sha256";
  if (/^[a-f0-9]{40}$/i.test(v)) return "sha1";
  if (/^[a-f0-9]{32}$/i.test(v)) return "md5";
  if (DOMAIN.test(v)) return "domain";
  return null;
}
