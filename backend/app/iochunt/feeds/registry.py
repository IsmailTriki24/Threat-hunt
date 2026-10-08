from app.iochunt.feeds.abusech import FeodoFeed, ThreatFoxFeed, UrlhausCsvFeed
from app.iochunt.feeds.base import Feed
from app.iochunt.feeds.generic import StixBundleFeed, TextListFeed
from app.iochunt.feeds.platforms import MispFeed, OtxFeed, TrendSuspiciousObjectsFeed

FEEDS: dict[str, type[Feed]] = {
    c.feed_type: c
    for c in (
        UrlhausCsvFeed,
        FeodoFeed,
        ThreatFoxFeed,
        OtxFeed,
        MispFeed,
        TrendSuspiciousObjectsFeed,
        TextListFeed,
        StixBundleFeed,
    )
}


def build(feed_type: str, config: dict[str, object] | None = None, secrets: dict[str, str] | None = None) -> Feed:
    cls = FEEDS.get(feed_type)
    if cls is None:
        raise KeyError(feed_type)
    return cls(cls.config_model.model_validate(config or {}), secrets)
