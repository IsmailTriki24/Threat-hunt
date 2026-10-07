"""Zeek JSON logs (conn.log, dns.log) → canonical events."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.connectors._util import epoch_to_iso, finish, str_list, strict_int, text
from app.connectors.base import Connector, NormalizationError
from app.events.schema import EventIn


class ZeekConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sensor: str | None = Field(default=None, max_length=256)  # used as host.hostname


class ZeekConnector(Connector):
    connector_type = "zeek"
    display_name = "Zeek"
    config_model = ZeekConfig

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        cfg: ZeekConfig = self.config  # type: ignore[assignment]
        path = text(raw.get("_path"))
        if path is None:
            path = "dns" if "query" in raw else "conn" if "proto" in raw else None
        if path not in ("conn", "dns"):
            raise NormalizationError(f"zeek log type {path!r} is not supported")
        ts = raw.get("ts")
        try:
            timestamp = epoch_to_iso(ts)
        except NormalizationError:
            if isinstance(ts, str) and ts:
                timestamp = ts  # ISO output format (json-streaming / LogAscii::use_json with iso8601)
            else:
                raise
        src_ip, dst_ip = text(raw.get("id.orig_h")), text(raw.get("id.resp_h"))
        net = {
            "protocol": (text(raw.get("proto")) or "").lower() or None,
            "src_ip": src_ip,
            "src_port": strict_int(raw.get("id.orig_p"), "id.orig_p"),
            "dst_ip": dst_ip,
            "dst_port": strict_int(raw.get("id.resp_p"), "id.resp_p"),
            "direction": "outbound",
        }
        doc: dict[str, Any] = {
            "timestamp": timestamp,
            "source": "zeek",
            "outcome": "success",
            "host": {"hostname": cfg.sensor},
            "original_id": text(raw.get("uid")) and f"{cfg.sensor or 'zeek'}:{path}:{text(raw.get('uid'))}",
            "raw": raw,
        }
        if path == "conn":
            sent, got = strict_int(raw.get("orig_bytes"), "orig_bytes"), strict_int(raw.get("resp_bytes"), "resp_bytes")
            net["bytes"] = (sent or 0) + (got or 0) if (sent is not None or got is not None) else None
            doc.update(event_type="network_connection", action="connection", network=net)
        else:
            doc.update(
                event_type="dns_query",
                action="dns_query",
                network=net,
                dns={
                    "question": text(raw.get("query")),
                    "query_type": text(raw.get("qtype_name")),
                    "answers": str_list(raw.get("answers")),
                },
            )
        return finish(doc)
