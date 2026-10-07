"""Suricata EVE JSON (alert, dns, flow) → canonical events."""

from typing import Any

from app.connectors._util import finish, iso_timestamp, obj, str_list, strict_int, text
from app.connectors.base import Connector, NormalizationError
from app.events.schema import EventIn

_SEVERITY = {1: 85, 2: 60, 3: 35}


class SuricataConnector(Connector):
    connector_type = "suricata"
    display_name = "Suricata"

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        kind = text(raw.get("event_type"))
        if kind not in ("alert", "dns", "flow"):
            raise NormalizationError(f"suricata event_type {kind!r} is not supported")
        net: dict[str, Any] = {
            "protocol": (text(raw.get("proto")) or "").lower() or None,
            "src_ip": text(raw.get("src_ip")),
            "src_port": strict_int(raw.get("src_port"), "src_port"),
            "dst_ip": text(raw.get("dest_ip")),
            "dst_port": strict_int(raw.get("dest_port"), "dest_port"),
            "direction": "outbound",
        }
        flow_id = text(raw.get("flow_id"))
        doc: dict[str, Any] = {
            "timestamp": iso_timestamp(raw.get("timestamp")),
            "source": "suricata",
            "network": net,
            "raw": raw,
            "host": {"hostname": text(raw.get("host"))},
            # alerts on the same flow can repeat; include signature id + timestamp for a stable, unique key
            "original_id": None,
        }
        if kind == "alert":
            alert = obj(raw.get("alert"))
            sev = _SEVERITY.get(strict_int(alert.get("severity"), "severity") or 0, 35)
            sig = text(alert.get("signature")) or "Suricata alert"
            category = text(alert.get("category"))
            doc.update(
                event_type="alert",
                action="ids_alert",
                outcome="unknown",
                severity=sev,
                message=sig[:1024],
                tags=[category] if category else [],
                labels={k: v for k, v in {"signature_id": text(alert.get("signature_id"))}.items() if v},
            )
            if flow_id:
                doc["original_id"] = (
                    f"suricata:alert:{flow_id}:{text(alert.get('signature_id'))}:{raw.get('timestamp')}"
                )
        elif kind == "dns":
            dns = obj(raw.get("dns"))
            answers = dns.get("answers")
            doc.update(
                event_type="dns_query",
                action="dns_query",
                outcome="success",
                dns={
                    "question": text(dns.get("rrname")),
                    "query_type": text(dns.get("rrtype")),
                    "answers": [
                        a
                        for a in (
                            text(obj(x).get("rdata")) for x in (answers if isinstance(answers, list) else [])[:32]
                        )
                        if a
                    ]
                    or str_list(answers),
                },
            )
            if flow_id:
                doc["original_id"] = f"suricata:dns:{flow_id}:{text(dns.get('id'))}:{raw.get('timestamp')}"
        else:
            flow = obj(raw.get("flow"))
            sent, got = (
                strict_int(flow.get("bytes_toserver"), "bytes_toserver"),
                strict_int(flow.get("bytes_toclient"), "bytes_toclient"),
            )
            net["bytes"] = (sent or 0) + (got or 0) if (sent is not None or got is not None) else None
            doc.update(event_type="network_connection", action="flow", outcome="success")
            if flow_id:
                doc["original_id"] = f"suricata:flow:{flow_id}:{raw.get('timestamp')}"
        return finish(doc)
