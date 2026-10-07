"""IOC extraction from telemetry. Pure functions; every candidate is validated, normalised and typed.
Regexes are linear-time (no nested quantifiers) and inputs are length-capped, so hostile event
content cannot cause catastrophic backtracking."""

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Literal

IocType = Literal["ip", "domain", "url", "sha256", "sha1", "md5", "email"]
MAX_TEXT = 8192

_URL = re.compile(r"https?://[^\s\"'<>`|^{}\\]{1,512}", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}$")
_HEX = {
    "md5": re.compile(r"^[a-f0-9]{32}$"),
    "sha1": re.compile(r"^[a-f0-9]{40}$"),
    "sha256": re.compile(r"^[a-f0-9]{64}$"),
}

_INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
        "ff00::/8",
        "::/128",
    )
]
# File extensions that look like TLDs but are not hosts in practice.
_NOT_TLDS = {
    "exe",
    "dll",
    "ps1",
    "bat",
    "cmd",
    "sys",
    "tmp",
    "log",
    "txt",
    "dmp",
    "docx",
    "docm",
    "xlsx",
    "js",
    "vbs",
    "lnk",
    "zip",
}
_INTERNAL_SUFFIXES = (".local", ".localdomain", ".internal", ".lan", ".home.arpa", ".in-addr.arpa", ".ip6.arpa")


@dataclass(frozen=True)
class Candidate:
    type: IocType
    value: str
    context: str


def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True  # unparseable values are never extracted
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def normalize(type_: str, value: str) -> str | None:
    """Return the canonical form of an IOC or None if invalid for the type."""
    v = value.strip()
    if not v or len(v) > 2048:
        return None
    if type_ == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None
    if type_ in _HEX:
        return v.lower() if _HEX[type_].match(v.lower()) else None
    if type_ == "domain":
        v = v.lower().rstrip(".")
        return v if _DOMAIN.match(v) and v.rsplit(".", 1)[-1] not in _NOT_TLDS else None
    if type_ == "email":
        v = v.lower()
        return v if len(v) <= 320 and _EMAIL.fullmatch(v) else None
    if type_ == "url":
        m = _URL.fullmatch(v)
        return v if m else None
    return None


def _get(doc: dict[str, Any], path: str) -> Any:
    cur: Any = doc
    for p in path.split("."):
        cur = cur.get(p) if isinstance(cur, dict) else None
    return cur


_DIRECT: list[tuple[str, IocType]] = [
    ("network.dst_ip", "ip"),
    ("network.src_ip", "ip"),
    ("auth.source_ip", "ip"),
    ("network.dst_domain", "domain"),
    ("dns.question", "domain"),
    ("process.hash.sha256", "sha256"),
    ("process.hash.sha1", "sha1"),
    ("process.hash.md5", "md5"),
    ("file.hash.sha256", "sha256"),
    ("file.hash.sha1", "sha1"),
    ("file.hash.md5", "md5"),
]
_TEXT_FIELDS = ["process.command_line", "process.parent.command_line", "message", "file.path", "registry.value"]


def extract(doc: dict[str, Any]) -> list[Candidate]:
    out: dict[tuple[str, str], Candidate] = {}

    def add(type_: IocType, raw: Any, context: str) -> None:
        if not isinstance(raw, str):
            return
        value = normalize(type_, raw)
        if value is None:
            return
        if type_ == "ip" and is_internal_ip(value):
            return
        if type_ == "domain" and value.endswith(_INTERNAL_SUFFIXES):
            return
        out.setdefault((type_, value), Candidate(type_, value, context))

    for path, type_ in _DIRECT:
        add(type_, _get(doc, path), path)
    for answer in _get(doc, "dns.answers") or []:
        add("ip", answer, "dns.answers")
    for path in _TEXT_FIELDS:
        text = _get(doc, path)
        if not isinstance(text, str):
            continue
        text = text[:MAX_TEXT]
        for url in _URL.findall(text):
            url = url.rstrip(".,;)")
            add("url", url, path)
            host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split("?")[0].split(":")[0].split("@")[-1]
            if _IPV4.fullmatch(host):
                add("ip", host, path)
            else:
                add("domain", host, path)
        for email in _EMAIL.findall(text):
            add("email", email, path)
        for ip in _IPV4.findall(text):
            add("ip", ip, path)
    return list(out.values())
