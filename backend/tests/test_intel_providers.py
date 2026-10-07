"""Every external adapter against mocked remote services, including hostile and failing responses."""

import base64
import json

import httpx
import pytest

from app.core import ssrf
from app.intel.providers import PROVIDERS, base
from app.intel.providers.base import Context

PUBLIC = "93.184.216.34"


@pytest.fixture
def remote(monkeypatch):
    state = {"handler": lambda r: httpx.Response(404), "requests": []}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        return state["handler"](request)

    async def resolve(host, port):
        return {"internal.example": ["10.1.1.1"]}.get(host, [host if host[0].isdigit() else PUBLIC])

    monkeypatch.setattr(base, "HTTP_TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(base, "RESOLVER", resolve)
    return state


def ctx(**secrets):
    return Context({"url": "https://misp.example.org"}, secrets)


async def run(key, type_, value, **secrets):
    return await PROVIDERS[key].lookup(ctx(**secrets), type_, value)


# ---- ThreatFox ---------------------------------------------------------------------------------------------
async def test_threatfox_hit_sends_auth_key_and_returns_relations(remote):
    remote["handler"] = lambda r: httpx.Response(
        200,
        json={
            "query_status": "ok",
            "data": [
                {
                    "ioc": "203.0.113.5:443",
                    "malware_printable": "Cobalt Strike",
                    "confidence_level": 80,
                    "threat_type": "botnet_cc",
                    "tags": ["cs"],
                }
            ],
        },
    )
    r = await run("threatfox", "ip", "203.0.113.5", auth_key="K")
    req = remote["requests"][0]
    assert req.headers["auth-key"] == "K" and json.loads(req.content)["search_term"] == "203.0.113.5"
    assert (r.status, r.verdict, r.confidence) == ("ok", "malicious", 80)
    assert [(x.kind, x.type, x.value) for x in r.relations] == [("indicates", "malware", "Cobalt Strike")]


@pytest.mark.parametrize(
    "provider,body,expected",
    [
        ("threatfox", {"query_status": "no_result"}, "not_found"),
        ("urlhaus", {"query_status": "no_results"}, "not_found"),
        ("threatfox", {"query_status": "ok", "data": "oops"}, "error"),
        ("urlhaus", {"query_status": "weird"}, "error"),
    ],
)
async def test_abusech_not_found_and_malformed(remote, provider, body, expected):
    remote["handler"] = lambda r: httpx.Response(200, json=body)
    assert (await run(provider, "domain", "x.example", auth_key="K")).status == expected


# ---- URLhaus -------------------------------------------------------------------------------------------------
async def test_urlhaus_url_and_payload_endpoints(remote):
    remote["handler"] = lambda r: httpx.Response(
        200, json={"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["exe"]}
    )
    r = await run("urlhaus", "url", "http://evil.example/a.exe", auth_key="K")
    assert r.verdict == "malicious" and r.confidence == 90
    assert str(remote["requests"][0].url).endswith("/v1/url/") and b"url=http" in remote["requests"][0].content
    await run("urlhaus", "sha256", "a" * 64, auth_key="K")
    assert str(remote["requests"][1].url).endswith("/v1/payload/") and b"sha256_hash=" in remote["requests"][1].content


# ---- OTX --------------------------------------------------------------------------------------------------------
async def test_otx_pulses_and_adversaries(remote):
    remote["handler"] = lambda r: httpx.Response(
        200,
        json={
            "pulse_info": {
                "count": 4,
                "pulses": [{"name": "Campaign X", "adversary": "APT-Fictional", "tags": ["c2"]}, {"name": "p2"}],
            }
        },
    )
    r = await run("otx", "domain", "evil.example", api_key="K")
    assert remote["requests"][0].headers["x-otx-api-key"] == "K" and "/domain/evil.example/general" in str(
        remote["requests"][0].url
    )
    assert r.verdict == "malicious" and r.relations[0].type == "threat_actor" and r.relations[0].kind == "attributed-to"
    remote["handler"] = lambda r: httpx.Response(200, json={"pulse_info": {"count": 1, "pulses": [{"name": "one"}]}})
    assert (await run("otx", "ip", "203.0.113.5", api_key="K")).verdict == "suspicious"
    remote["handler"] = lambda r: httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}})
    assert (await run("otx", "ip", "203.0.113.5", api_key="K")).status == "not_found"
    remote["handler"] = lambda r: httpx.Response(404)
    assert (await run("otx", "ip", "203.0.113.5", api_key="K")).status == "not_found"


async def test_otx_url_value_is_percent_encoded_in_path(remote):
    remote["handler"] = lambda r: httpx.Response(404)
    await run("otx", "url", "http://evil.example/a?b=c#d", api_key="K")
    assert "/url/http%3A%2F%2Fevil.example%2Fa%3Fb%3Dc%23d/general" in str(remote["requests"][0].url)


# ---- VirusTotal ---------------------------------------------------------------------------------------------------
async def test_virustotal_verdict_thresholds_and_url_id(remote):
    def reply(m, s, h):
        return lambda r: httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": m, "suspicious": s, "harmless": h, "undetected": 10},
                        "tags": ["x"],
                        "popular_threat_classification": {"suggested_threat_label": "trojan.x"},
                    }
                }
            },
        )

    remote["handler"] = reply(12, 0, 3)
    r = await run("virustotal", "sha256", "a" * 64, api_key="K")
    assert r.verdict == "malicious" and r.confidence >= 90 and remote["requests"][0].headers["x-apikey"] == "K"
    assert r.data["threat_label"] == "trojan.x"
    remote["handler"] = reply(2, 0, 50)
    assert (await run("virustotal", "ip", "203.0.113.5", api_key="K")).verdict == "suspicious"
    remote["handler"] = reply(0, 0, 60)
    assert (await run("virustotal", "domain", "example.com", api_key="K")).verdict == "benign"
    await run("virustotal", "url", "http://a.example/x", api_key="K")
    ident = base64.urlsafe_b64encode(b"http://a.example/x").decode().rstrip("=")
    assert str(remote["requests"][-1].url).endswith(f"/urls/{ident}")
    remote["handler"] = lambda r: httpx.Response(404)
    assert (await run("virustotal", "md5", "c" * 32, api_key="K")).status == "not_found"


# ---- MISP ---------------------------------------------------------------------------------------------------------
async def test_misp_attribute_search_and_to_ids(remote):
    remote["handler"] = lambda r: httpx.Response(
        200,
        json={
            "response": {
                "Attribute": [
                    {
                        "to_ids": True,
                        "category": "Network activity",
                        "Event": {"info": "Phishing wave"},
                        "Tag": [{"name": "tlp:amber"}],
                    }
                ]
            }
        },
    )
    r = await run("misp", "domain", "evil.example", api_key="MKEY")
    req = remote["requests"][0]
    assert str(req.url) == f"https://{PUBLIC}/attributes/restSearch" and req.headers["authorization"] == "MKEY"
    body = json.loads(req.content)
    assert body["value"] == "evil.example" and body["enforceWarninglist"] is True
    assert r.verdict == "malicious" and r.data["events"] == ["Phishing wave"]
    remote["handler"] = lambda r: httpx.Response(200, json={"response": {"Attribute": [{"to_ids": False}]}})
    assert (await run("misp", "ip", "203.0.113.5", api_key="K")).verdict == "suspicious"
    remote["handler"] = lambda r: httpx.Response(200, json={"response": {"Attribute": []}})
    assert (await run("misp", "ip", "203.0.113.5", api_key="K")).status == "not_found"


async def test_misp_url_pointing_inside_the_network_is_blocked(remote):
    c = Context({"url": "https://internal.example"}, {"api_key": "K"})
    with pytest.raises(ssrf.SsrfError):
        await PROVIDERS["misp"].lookup(c, "ip", "203.0.113.5")
    assert remote["requests"] == []


# ---- shared failure handling ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "key,secret",
    [
        ("threatfox", "auth_key"),
        ("urlhaus", "auth_key"),
        ("otx", "api_key"),
        ("virustotal", "api_key"),
        ("misp", "api_key"),
    ],
)
@pytest.mark.parametrize(
    "status,needle", [(401, "authentication"), (403, "authentication"), (429, "rate limited"), (500, "provider error")]
)
async def test_http_failures_become_error_results(remote, key, secret, status, needle):
    remote["handler"] = lambda r: httpx.Response(status)
    res = await run(
        key, "ip" if key != "urlhaus" else "domain", "203.0.113.5" if key != "urlhaus" else "x.example", **{secret: "K"}
    )
    assert res.status == "error" and needle in res.summary and res.verdict == "unknown"


@pytest.mark.parametrize(
    "key,secret", [("threatfox", "auth_key"), ("otx", "api_key"), ("virustotal", "api_key"), ("misp", "api_key")]
)
async def test_non_json_and_wrong_shape_responses_are_contained(remote, key, secret):
    remote["handler"] = lambda r: httpx.Response(200, text="<html>not json</html>")
    with pytest.raises(ValueError):  # converted into an error result by the service layer
        await run(key, "ip", "203.0.113.5", **{secret: "K"})
    remote["handler"] = lambda r: httpx.Response(200, json=["unexpected", "list"])
    res = await run(key, "ip", "203.0.113.5", **{secret: "K"})
    assert res.status in ("error", "not_found")


async def test_hostile_response_content_is_clipped_and_stored_as_data(remote):
    huge = "A" * 100_000
    remote["handler"] = lambda r: httpx.Response(
        200,
        json={
            "query_status": "ok",
            "data": [
                {
                    "malware_printable": "<script>alert(1)</script>" + huge,
                    "confidence_level": 99,
                    "tags": [huge] * 50,
                    "threat_type": huge,
                }
            ],
        },
    )
    res = await run("threatfox", "ip", "203.0.113.5", auth_key="K")
    assert len(json.dumps(res.data)) <= base.MAX_DATA_BYTES and all(len(m) <= 80 for m in res.data["malware"])
    assert len(res.summary) < 500
    assert res.relations and len(res.relations[0].value) <= 80
