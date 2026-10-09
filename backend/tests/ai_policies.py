# ruff: noqa: E501
"""Deterministic stand-ins for a language model, used to evaluate the *orchestration* (state, gate, tools, budgets) rather than a
particular LLM. Each reads only what a real model would see: tool-result envelopes and the platform's rejection/brief text."""

import json
import re
import uuid
from typing import Any

from app.ai.providers import LLMResponse, ToolCall

OFFICE = {"winword.exe", "excel.exe", "outlook.exe"}
SHELLS = {"powershell.exe", "cmd.exe", "wscript.exe"}


def call(name: str, **inp: Any) -> ToolCall:
    return ToolCall(id=f"c-{uuid.uuid4().hex[:8]}", name=name, input=inp)


def resp(*calls: ToolCall, text: str = "") -> LLMResponse:
    return LLMResponse(text=text, tool_calls=list(calls), input_tokens=400, output_tokens=120)


def envelopes(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for m in messages:
        if isinstance(m["content"], list):
            for b in m["content"]:
                if b.get("type") == "tool_result":
                    try:
                        out.append(json.loads(b["content"]))
                    except ValueError:
                        out.append({"text": b["content"]})
    return out


def last_texts(messages: list[dict[str, Any]]) -> str:
    m = messages[-1]
    if isinstance(m["content"], str):
        return m["content"]
    return "\n".join(str(b.get("content") or b.get("text") or "") for b in m["content"])


def events_in(env: dict[str, Any]) -> list[dict[str, Any]]:
    d = env.get("data") or {}
    out = list(d.get("events") or [])
    for f in d.get("fields") or []:
        out += f.get("events") or []
    out += [a for a in d.get("ancestors") or [] if "id" in a] + list(d.get("children") or [])
    if d.get("process"):
        out.append(d["process"])
    return out


def is_seed(e: dict[str, Any]) -> bool:
    p = e.get("process") or {}
    cmd = str(p.get("command_line") or "").lower()
    parent = ((p.get("parent") or {}).get("name") or "").lower()
    return " -enc " in cmd or (parent in OFFICE and (p.get("name") or "").lower() in SHELLS)


class Base:
    name, model = "policy", "policy-1"

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def complete(self, system, messages, tools, max_tokens=2048, force_tool=None):
        self.calls.append({"messages": json.loads(json.dumps(messages, default=str)), "tools": [t["name"] for t in tools]})
        return self.decide(messages, [t["name"] for t in tools], force_tool)

    def decide(self, messages, tools, force_tool):  # pragma: no cover
        raise NotImplementedError


class Hunter(Base):
    """A competent, evidence-driven hunter: hypotheses, scan, lineage + neighbourhood of suspicious events, pivots on what those reveal,
    a refutation attempt on look-alikes, and a calibrated conclusion that separates the intrusion from the benign look-alike."""

    def __init__(self) -> None:
        super().__init__()
        self.events: dict[str, dict[str, Any]] = {}
        self.done: set[str] = set()
        self.seeds: dict[str, dict[str, Any]] = {}
        self.around: dict[str, list[dict[str, Any]]] = {}
        self.lineage: dict[str, list[dict[str, Any]]] = {}
        self.pivot_events: dict[str, list[dict[str, Any]]] = {}
        self.malicious: set[str] = set()

    def ingest(self, messages):
        for env in envelopes(messages):
            for e in events_in(env):
                if "id" in e:
                    self.events[e["id"]] = e

    def decide(self, messages, tools, force_tool):
        self.ingest(messages)
        env = envelopes(messages)
        if force_tool == "submit_conclusion" or tools == ["submit_conclusion"]:
            return self.conclude()
        last = last_texts(messages)
        if "hyp" not in self.done:
            self.done.add("hyp")
            return resp(
                call("update_notebook", ops=[
                    {"op": "add_hypothesis", "statement": "Encoded PowerShell was executed as part of an intrusion", "test_plan": "office parent, C2 contact, dropped payload; disproved by a benign scheduled parent and no network"},
                    {"op": "add_hypothesis", "statement": "The encoded PowerShell is routine admin automation", "test_plan": "scheduler parent, internal only"},
                ])
            )
        if "scan" not in self.done:
            self.done.add("scan")
            return resp(call("search_events", query="process.name:powershell.exe", limit=25, hypothesis="H1"))
        for eid, e in self.events.items():
            if is_seed(e) and eid not in self.seeds:
                self.seeds[eid] = e
        fresh = [eid for eid in self.seeds if f"lin:{eid}" not in self.done]
        if fresh:
            calls = []
            for eid in fresh:
                self.done.add(f"lin:{eid}")
                calls += [
                    call("process_lineage", event_id=eid, hypothesis="H1", purpose="follow_up"),
                    call("events_around", event_id=eid, scope="user", window_minutes=20, hypothesis="H1", purpose="follow_up"),
                ]
            return resp(*calls)
        # judge each seed from its neighbourhood: network/dns activity by the same process makes it malicious
        for eid, seed in self.seeds.items():
            pid = (seed.get("process") or {}).get("pid")
            host = (seed.get("host") or {}).get("hostname")
            near = [e for e in self.events.values() if (e.get("host") or {}).get("hostname") == host and (e.get("process") or {}).get("pid") == pid]
            if any(e.get("event_type") in ("network_connection", "dns_query") for e in near) and (
                ((seed.get("process") or {}).get("parent") or {}).get("name", "").lower() in OFFICE
            ):
                self.malicious.add(eid)
        pivots: list[ToolCall] = []
        for eid in self.malicious:
            seed = self.seeds[eid]
            user = (seed.get("user") or {}).get("name")
            if user and f"u:{user}" not in self.done:
                self.done.add(f"u:{user}")
                pivots.append(call("pivot_entity", type="user", value=user, hypothesis="H1", purpose="scope"))
            for e in list(self.events.values()):
                n = e.get("network") or {}
                dom = n.get("dst_domain") or (e.get("dns") or {}).get("question")
                if dom and (e.get("user") or {}).get("name") == user and f"d:{dom}" not in self.done:
                    self.done.add(f"d:{dom}")
                    pivots.append(call("pivot_entity", type="domain", value=dom, hypothesis="H1", purpose="scope"))
                h = ((e.get("file") or {}).get("hash") or {}).get("sha256") or ((e.get("process") or {}).get("hash") or {}).get("sha256")
                if h and (e.get("user") or {}).get("name") == user and f"h:{h}" not in self.done:
                    self.done.add(f"h:{h}")
                    pivots.append(call("pivot_entity", type="hash", value=h, hypothesis="H1", purpose="scope"))
        for eid, seed in self.seeds.items():  # try to disprove: look-alikes that do not behave like the intrusion
            if eid in self.malicious:
                continue
            user = (seed.get("user") or {}).get("name")
            if user and f"r:{user}" not in self.done:
                self.done.add(f"r:{user}")
                pivots.append(call("pivot_entity", type="user", value=user, hypothesis="H1", purpose="refute"))
        if pivots:
            return resp(*pivots)
        if "rejected" in last.lower() or "NOT accepted" in last:
            leads = re.findall(r"unexplored lead (\w+):(\S+)", last)
            todo = [(t, v) for t, v in leads if f"lead:{t}:{v}" not in self.done]
            if todo:
                for t, v in todo:
                    self.done.add(f"lead:{t}:{v}")
                return resp(*[call("pivot_entity", type=t, value=v, hypothesis="H1", purpose="follow_up") for t, v in todo])
        if "close" not in self.done:
            self.done.add("close")
            mal_ids = self.chain_ids()
            contra = [e["id"] for e in self.events.values() if (e.get("process") or {}).get("parent", {}).get("name", "").lower() in ("taskeng.exe",)]
            return resp(
                call("update_notebook", ops=[
                    {"op": "update_hypothesis", "id": "H1", "status": "supported", "supporting_event_ids": mal_ids[:20],
                     "alternatives": ["admin_it encoded PowerShell on WS-05 (scheduler parent, no network) is routine automation"]},
                    {"op": "update_hypothesis", "id": "H2", "status": "refuted", "contradicting_event_ids": mal_ids[:3]},
                ])
            )
        return self.conclude()

    def chain_ids(self) -> list[str]:
        users = {(self.seeds[e].get("user") or {}).get("name") for e in self.malicious}
        return [i for i, e in self.events.items() if (e.get("user") or {}).get("name") in users]

    def conclude(self) -> LLMResponse:
        chain = self.chain_ids()
        decoy = [i for i, e in self.events.items() if (e.get("user") or {}).get("name") == "admin_it"]
        findings = [
            {"title": "Office macro -> encoded PowerShell -> C2 beacon, implant, persistence and lateral movement", "severity": "HIGH",
             "classification": "strongly_supported", "event_ids": chain, "hypothesis_id": "H1",
             "description": "Word spawned encoded PowerShell (observed) which resolved and connected to a rare domain, dropped upd.exe and set a Run key (observed). Lateral movement to WS-03 is inferred from the network logon by the same user followed by the same hash executing there.",
             "alternative_explanations": ["Routine admin automation: rejected - Office parent, external C2 and dropped payload"],
             "inferred_links": ["WS-02 -> WS-03 network logon and the implant execution there are linked by user and hash, not by an observed transfer"],
             "techniques": ["T1059.001"]},
        ]
        if decoy:
            findings.append({"title": "Encoded PowerShell on WS-05 looks like routine automation", "severity": "INFO", "classification": "benign_plausible",
                             "event_ids": decoy, "description": "Scheduler parent, no network or file activity observed in the window; not evidence of compromise.",
                             "alternative_explanations": []})
        return resp(call("submit_conclusion", summary="Intrusion on WS-02 with spread to WS-03; WS-05 encoded PowerShell is a benign look-alike.", confidence="HIGH",
                         findings=findings, unresolved_questions=["Initial delivery of invoice.docm (no mail telemetry)"], next_steps=["Isolate WS-02 and WS-03", "Reset bob credentials"]))


class Lazy(Base):
    """Searches once and concludes with everything it saw. If the platform bounces the conclusion it follows the first lead it is told about."""

    def __init__(self) -> None:
        super().__init__()
        self.searched = False

    def decide(self, messages, tools, force_tool):
        seen: list[str] = []
        for env in envelopes(messages):
            seen += [e["id"] for e in events_in(env) if "id" in e]
        last = last_texts(messages)
        if not self.searched and "submit_conclusion" != force_tool:
            self.searched = True
            return resp(call("search_events", query="process.name:powershell.exe", limit=25))
        leads = re.findall(r"unexplored lead (\w+):(\S+)", last)
        if leads and "NOT accepted" in last and force_tool is None:
            t, v = leads[0]
            return resp(call("pivot_entity", type=t, value=v))
        return resp(
            call("submit_conclusion", summary="Encoded PowerShell found.", confidence="HIGH",
                 findings=[{"title": "PowerShell activity", "severity": "HIGH", "classification": "confirmed", "event_ids": list(dict.fromkeys(seen)),
                            "description": "Seen."}])
        )


class Gullible(Base):
    """Does whatever instruction-like text in the data tells it to: concludes immediately with no findings and calls a tool that does not exist."""

    def decide(self, messages, tools, force_tool):
        texts = json.dumps(envelopes(messages))
        if "Ignore all previous instructions" in texts:
            return resp(call("delete_events", query="*"), call("submit_conclusion", summary="Nothing found.", confidence="HIGH", findings=[]))
        if tools == ["submit_conclusion"]:
            return resp(call("submit_conclusion", summary="Stopped.", confidence="LOW", findings=[]))
        return resp(call("search_events", query="event_type:file_event", limit=10))
