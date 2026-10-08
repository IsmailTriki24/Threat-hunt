"""YAML loading for untrusted rule content: safe types only, no anchors/aliases (billion-laughs), bounded size and depth."""

from typing import Any

import yaml
from yaml.nodes import Node

MAX_BYTES = 64 * 1024
MAX_DEPTH = 12


class YamlError(ValueError):
    pass


class _NoAliasLoader(yaml.SafeLoader):  # type: ignore[misc]
    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        if self.check_event(yaml.events.AliasEvent):
            raise yaml.YAMLError("YAML aliases/anchors are not allowed")
        return super().compose_node(parent, index)


def _depth(obj: Any, d: int = 1) -> int:
    if d > MAX_DEPTH:
        return d
    if isinstance(obj, dict):
        return max([d] + [_depth(v, d + 1) for v in obj.values()])
    if isinstance(obj, list):
        return max([d] + [_depth(v, d + 1) for v in obj])
    return d


def load(text: str) -> dict[str, Any]:
    if len(text.encode()) > MAX_BYTES:
        raise YamlError(f"rule is larger than {MAX_BYTES // 1024} KiB")
    try:
        doc = yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506  # nosec B506 (SafeLoader subclass)
    except yaml.YAMLError as exc:
        raise YamlError(f"invalid YAML: {str(exc).splitlines()[0][:200]}") from None
    if not isinstance(doc, dict):
        raise YamlError("rule must be a YAML mapping")
    if _depth(doc) > MAX_DEPTH:
        raise YamlError("rule is nested too deeply")
    return doc
