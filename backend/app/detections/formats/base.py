"""Detection-format abstraction. A format turns rule *source text* into a `ParsedRule`: metadata plus a `Condition` tree that every
backend can execute (OpenSearch compile, local evaluator). New formats (KQL, YARA-L, native JSON…) implement this one class."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from app.events.search.query import Condition

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class RuleError(ValueError):
    """The rule cannot be parsed at all."""


@dataclass
class ParsedRule:
    title: str
    description: str = ""
    severity: str = "MEDIUM"
    status: str = ""  # the author's declared maturity (informational)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    author: str = ""
    techniques: list[str] = field(default_factory=list)  # ATT&CK ids declared by tags, e.g. T1059.001
    tactics: list[str] = field(default_factory=list)
    where: Condition | None = None
    selections: dict[str, Condition] = field(default_factory=dict)  # named parts, for explainability
    unsupported: list[str] = field(default_factory=list)  # reasons the rule cannot be executed here
    warnings: list[str] = field(default_factory=list)

    @property
    def executable(self) -> bool:
        return self.where is not None and not self.unsupported


class DetectionFormat(ABC):
    format_id: ClassVar[str]
    display_name: ClassVar[str]
    description: ClassVar[str] = ""

    @abstractmethod
    def parse(self, content: str) -> ParsedRule:
        """Parse + compile. Raise RuleError when unparseable; report merely unexecutable constructs via `unsupported`."""
