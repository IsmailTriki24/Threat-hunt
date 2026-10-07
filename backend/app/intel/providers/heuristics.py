# ruff: noqa: E501
"""Offline heuristics. Never asserts 'malicious' — only 'suspicious' hints with modest confidence — and works with no credentials."""

import ipaddress
import math
from collections import Counter
from urllib.parse import urlsplit

from app.intel.providers.base import Context, Provider, ProviderResult
from app.investigations.iocs import is_internal_ip

_SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "click",
    "country",
    "kim",
    "work",
    "support",
    "rest",
    "cyou",
}
_EXEC_EXT = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".scr", ".js", ".vbs", ".hta", ".msi", ".jar", ".lnk")
_EMPTY_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "MD5 of an empty file",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "SHA-1 of an empty file",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "SHA-256 of an empty file",
}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


class HeuristicsProvider(Provider):
    key = "heuristics"
    display_name = "Local heuristics"
    description = "Offline structural checks (address class, domain randomness, URL shape). No network, no credentials."
    supported_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    offline = True

    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult:
        reasons: list[str] = []
        if type_ == "ip":
            if is_internal_ip(value):
                return ProviderResult("ok", "benign", 60, "Internal / non-routable address", {"class": "internal"})
            return ProviderResult("not_found", summary="Public address; no structural signal")
        if type_ in _EMPTY_HASHES or value in _EMPTY_HASHES:
            return ProviderResult("ok", "benign", 90, _EMPTY_HASHES[value], {})
        if type_ in ("md5", "sha1", "sha256"):
            return ProviderResult("not_found", summary="Hash has no structural signal")
        if type_ == "domain":
            labels = value.split(".")
            sld = labels[-2] if len(labels) >= 2 else value
            if labels[-1] in _SUSPICIOUS_TLDS:
                reasons.append(f"TLD .{labels[-1]} is frequently abused")
            if any(label.startswith("xn--") for label in labels):
                reasons.append("punycode (possible homograph)")
            if len(sld) >= 12 and entropy(sld) >= 3.6:
                reasons.append(f"high-entropy name ({entropy(sld):.1f} bits/char), DGA-like")
            if len(labels) >= 6:
                reasons.append("unusually many subdomain labels")
            if sum(c.isdigit() for c in sld) >= max(4, len(sld) // 2):
                reasons.append("mostly digits")
        elif type_ == "url":
            parts = urlsplit(value)
            host = parts.hostname or ""
            try:
                ipaddress.ip_address(host)
                reasons.append("host is a raw IP address")
            except ValueError:
                pass
            if "@" in parts.netloc:
                reasons.append("credentials-style '@' in authority (obfuscation)")
            if parts.path.lower().endswith(_EXEC_EXT):
                reasons.append("URL points at an executable/script file")
            if "xn--" in host:
                reasons.append("punycode host")
            if len(value) > 300:
                reasons.append("very long URL")
        if not reasons:
            return ProviderResult("not_found", summary="No structural signal")
        confidence = min(55, 20 + 12 * len(reasons))
        return ProviderResult("ok", "suspicious", confidence, "; ".join(reasons)[:480], {"reasons": reasons[:6]})
