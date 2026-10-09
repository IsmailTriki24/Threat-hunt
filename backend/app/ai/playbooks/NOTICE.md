# Third-party notice

The hunt playbooks in `data/` are distilled from the threat-hunting and threat-detection skills of
**Anthropic-Cybersecurity-Skills** by mahipal (<https://github.com/mukul975/Anthropic-Cybersecurity-Skills>),
licensed under the **Apache License 2.0** (a copy is in `UPSTREAM_LICENSE`). Source revision: `54a7988`.

Changes: the upstream procedures were read as text only (none of their code is included or executed). Each
playbook re-expresses the detection logic for this platform - queries are rewritten in this project's hunt query
language and checked by its parser, telemetry requirements are mapped to this project's event types, and
benign explanations, pivots and confirmation criteria were added. Every playbook lists the upstream skills it was
distilled from under `sources`.

This project is independent of, and not endorsed by, the upstream authors or Anthropic PBC.
