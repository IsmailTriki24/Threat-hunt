from app.intel.providers.base import Provider
from app.intel.providers.heuristics import HeuristicsProvider
from app.intel.providers.misp import MispProvider
from app.intel.providers.otx import OtxProvider
from app.intel.providers.threatfox import ThreatFoxProvider
from app.intel.providers.urlhaus import UrlhausProvider
from app.intel.providers.virustotal import VirusTotalProvider
from app.intel.providers.watchlist import WatchlistProvider

PROVIDERS: dict[str, Provider] = {
    p.key: p
    for p in (
        HeuristicsProvider(),
        WatchlistProvider(),
        ThreatFoxProvider(),
        UrlhausProvider(),
        OtxProvider(),
        VirusTotalProvider(),
        MispProvider(),
    )
}
# Configuration-only entry for TAXII feeds (not a lookup provider): see intel/taxii.py
TAXII_KEY = "taxii"
__all__ = ["PROVIDERS", "TAXII_KEY", "Provider"]
