from app.intel.providers.base import Context, Provider, ProviderResult


class WatchlistProvider(Provider):
    key = "watchlist"
    display_name = "Tenant watch-list"
    description = "Your own verdicts: manual entries, STIX/TAXII imports and analyst overrides. Offline; always on."
    supported_types = {"ip", "domain", "url", "md5", "sha1", "sha256", "email", "certificate"}
    offline = True

    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult:
        if not ctx.watch_verdict:
            return ProviderResult("not_found", summary="Not on the tenant watch-list")
        return ProviderResult(
            "ok", ctx.watch_verdict, ctx.watch_confidence or 70, f"Tenant watch-list says {ctx.watch_verdict}", {}
        )
