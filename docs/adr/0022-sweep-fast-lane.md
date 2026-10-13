# ADR 0022 — A fast lane for the hottest indicators

**Status:** accepted. Extends ADR 0019/0021.

**Problem.** One full pass over every validated indicator (1,238 here, plus behaviours) takes about as long as the window it covers, so on a production
SIEM the sweep settles 20-40 minutes behind real time. The most urgent indicators wait in the same queue as the least urgent.

**Why not separate tiers.** Giving each tier its own cursor opens a coverage gap whenever an indicator moves between tiers (its old tier has searched up to
one instant, the new tier starts at another). Keeping the guarantee simple matters more than saving the duplicate work.

**Decision: two lanes per source (`IocSweep.lane`).**
* **full** (unchanged): every item with its own exact cursor. It is the only coverage guarantee; nothing is ever missed because of the fast lane.
* **fast** (new): only the hottest indicators (at most `sweep_hot_size`, default 150) and the most severe behaviours (`sweep_hot_ioas`, default 5), with
  their own cursor kept `sweep_lag_minutes` behind real time. They are searched again by the full lane, so the hot set can change freely between windows;
  the duplicate hits are harmless because matches, alerts and case notes are unique per event. Built-in behaviours are not in the fast lane (too many searches).
* A tick runs the fast lane first with at most a third of the budget, then the full lane with the rest. A failing fast lane never stops the full lane.

**What "hot" means** (`sweep.hot_score`, only indicators scoring 300 or more qualify): already seen in our telemetry (+1000), supplied by the
organisation itself (manual / Trend Suspicious Objects, +600), a role that means live attacker infrastructure (botnet_cc, c2, ransomware, +300), seen
in the last day (+200) or three days (+100), a network indicator rather than a hash (+50). Confidence is deliberately not used: on the production data 969 of
1,241 validated indicators are at 80 or more (averages 89-99), so it separates nothing.

**Status.** The Data Sources column shows a "fast lane: N hot + M behaviours · X min behind" line; `fast_lane` is absent when `sweep_hot_size` and `sweep_hot_ioas` are 0.

**Exact-URL searches are budgeted per tick.** A hunt may spend `url_pattern_max` (10) exact-URL pattern searches once. A sweep ran that allowance on every chunk of
every pass (about 130 extra searches for 1,238 indicators), which is most of why a pass was slow. Each URL is already searched through its host, so the exact-URL
searches only help for logs that record a URL without a host. A sweep tick now shares `sweep_url_patterns` (default 5) of them across all its chunks.
