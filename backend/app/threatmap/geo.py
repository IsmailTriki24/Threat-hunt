"""IP classification and geolocation for the threat map.

Two rules shape this module:
* Only globally routable addresses are ever looked up. Private, loopback, link-local, CGNAT, documentation and other reserved ranges get
  a *class* (so the UI can say "internal"), never a location.
* A geolocation is a statistical approximation from a database, not the physical location of whoever uses the address. Callers must
  present it as such; nothing here (or in the API built on it) claims an attacker's whereabouts.

The provider is pluggable. `mmdb` reads any MaxMind-format database (GeoLite2, DB-IP Lite, ...) locally, so no lookup ever leaves the
platform and nothing external is called while rendering."""

import ipaddress
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

log = logging.getLogger("app.threatmap.geo")

IpClass = str  # public | private | loopback | link_local | cgnat | multicast | reserved | unspecified | invalid

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# RFC 1918 and unique-local (RFC 4193). Python's `is_private` is broader (it also covers documentation and reserved blocks, which are
# not "internal networks"), so private is decided explicitly and everything else non-global is "reserved".
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def classify_ip(value: str | None) -> IpClass:
    """Classify an address. Only `public` addresses may be geolocated."""
    if not value:
        return "invalid"
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return "invalid"
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.version == 4 and ip in _CGNAT:
        return "cgnat"
    if any(ip.version == n.version and ip in n for n in _PRIVATE):
        return "private"
    if not ip.is_global:
        return "reserved"
    return "public"


def classify_with_own(value: str | None, own: "list[ipaddress.IPv4Network | ipaddress.IPv6Network]") -> IpClass:
    """`classify_ip`, plus `own` for public addresses inside the operator's declared address space (they are us, not remote)."""
    cls = classify_ip(value)
    if cls == "public" and own:
        ip = ipaddress.ip_address(str(value).strip())
        if any(ip.version == n.version and ip in n for n in own):
            return "own"
    return cls


def is_public(value: str | None) -> bool:
    return classify_ip(value) == "public"


def is_internal(value: str | None) -> bool:
    """Addresses that belong to a local/private network (not the public Internet)."""
    return classify_ip(value) in ("private", "loopback", "link_local", "cgnat")


@dataclass(frozen=True)
class GeoPoint:
    country: str  # ISO 3166-1 alpha-2
    country_name: str
    continent: str  # AF | AN | AS | EU | NA | OC | SA
    city: str
    region: str
    lat: float | None
    lon: float | None
    asn: int | None
    org: str


class GeoProvider(Protocol):
    name: str

    def lookup(self, ip: str) -> GeoPoint | None: ...

    def info(self) -> dict[str, Any]: ...


class NullProvider:
    """No GeoIP database configured: classification still works, locations are simply unavailable (never invented)."""

    name = "none"

    def lookup(self, ip: str) -> GeoPoint | None:
        return None

    def info(self) -> dict[str, Any]:
        return {"provider": "none", "available": False, "asn": False, "attribution": ""}


def _en(node: Any) -> str:
    return str((node or {}).get("names", {}).get("en", "")) if isinstance(node, dict) else ""


class MmdbProvider:
    """MaxMind-format reader: a City/Country database plus an optional ASN database."""

    name = "mmdb"

    def __init__(self, city_path: str, asn_path: str = "") -> None:
        import maxminddb

        self._city = maxminddb.open_database(city_path)
        self._asn = maxminddb.open_database(asn_path) if asn_path and Path(asn_path).is_file() else None
        self._city_type = str(self._city.metadata().database_type)
        self._build = int(self._city.metadata().build_epoch)

    def lookup(self, ip: str) -> GeoPoint | None:
        if not is_public(ip):
            return None
        rec: dict[str, Any] = self._city.get(ip) or {}  # type: ignore[assignment]
        asn: dict[str, Any] = (self._asn.get(ip) if self._asn else None) or {}  # type: ignore[assignment]
        country = (
            (rec.get("country") or {}).get("iso_code") or (rec.get("registered_country") or {}).get("iso_code") or ""
        )
        loc = rec.get("location") or {}
        lat, lon = loc.get("latitude"), loc.get("longitude")
        if not country and lat is None and not asn:
            return None
        subs = rec.get("subdivisions") or []
        return GeoPoint(
            country=str(country).upper(),
            country_name=_en(rec.get("country")),
            continent=str((rec.get("continent") or {}).get("code", "")),
            city=_en(rec.get("city")),
            region=_en(subs[0]) if subs else "",
            lat=float(lat) if lat is not None else None,
            lon=float(lon) if lon is not None else None,
            asn=int(asn["autonomous_system_number"]) if asn.get("autonomous_system_number") else None,
            org=str(asn.get("autonomous_system_organization", "")),
        )

    def info(self) -> dict[str, Any]:
        dbip = self._city_type.lower().startswith("dbip")
        return {
            "provider": self._city_type,
            "available": True,
            "asn": self._asn is not None,
            "built_epoch": self._build,
            "attribution": "IP geolocation by DB-IP (CC BY 4.0)" if dbip else "GeoIP data: MaxMind GeoLite2",
        }


class CachedGeo:
    """Memoises lookups (including misses) so one IP is resolved at most once per process, however many markers use it."""

    def __init__(self, provider: GeoProvider, size: int = 65536) -> None:
        self.provider = provider
        self.lookup = lru_cache(maxsize=size)(self._lookup)

    def _lookup(self, ip: str) -> GeoPoint | None:
        try:
            return self.provider.lookup(ip)
        except Exception:  # a corrupt record must not break a whole map request
            log.warning("geoip lookup failed", extra={"ip": ip})
            return None

    def info(self) -> dict[str, Any]:
        return self.provider.info()


def build_provider(kind: str, city_path: str, asn_path: str) -> GeoProvider:
    if kind == "none" or not city_path:
        return NullProvider()
    if kind != "mmdb":
        raise ValueError(f"unknown GEOIP_PROVIDER {kind!r}")
    if not Path(city_path).is_file():
        log.warning("GeoIP database not found; the threat map will show no locations", extra={"path": city_path})
        return NullProvider()
    return MmdbProvider(city_path, asn_path)


_geo: CachedGeo | None = None
_geo_key: tuple[str, str, str] | None = None


def get_geo(kind: str, city_path: str, asn_path: str) -> CachedGeo:
    """Process-wide provider, rebuilt only when the configuration changes."""
    global _geo, _geo_key
    key = (kind, city_path, asn_path)
    if _geo is None or _geo_key != key:
        _geo, _geo_key = CachedGeo(build_provider(kind, city_path, asn_path)), key
    return _geo
