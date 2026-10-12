# ADR 0017 — Light enterprise theme and shared UI kit

**Status:** accepted.

**Problem.** The UI had grown page by page: a dark-only palette with colours inlined at ~1,000 call sites, no icons, a flat 14-item sidebar, a header
that carried only tenant and sign-out, hand-rolled tabs/badges/modals in many places, five native `confirm()` dialogs, bare tables of varying quality,
raw Markdown shown as text on the case page, and pages that scrolled sideways. The same severity had five different looks.

**Decision.**
1. **Light theme, token-driven.** The brief asked for a refined light theme with the purple identity. Tokens live in CSS variables; Tailwind maps them
   to names. The legacy dark-tuned palette utilities are remapped centrally (see docs/design-system.md) instead of editing every call site, which kept
   the redesign reviewable and let existing tests keep their meaning. Accent text uses `#6457D8` (AA on white and on its tint); `#7568E9` stays the
   brand colour for graphics.
2. **One severity/status vocabulary** with icon + label + colour, so nothing depends on colour alone.
3. **A small shared kit, no new component library.** `lucide-react` (tree-shaken icons) and `@fontsource-variable/inter` (self-hosted, so the strict CSP
   and offline use are unaffected) are the only new dependencies. Overlays, menus, tabs, toasts, confirmations and empty/loading states are ~400 lines
   of in-house components with tests.
4. **A real shell.** Grouped navigation from a single model (`lib/nav.ts`, with a test that every item has a page), breadcrumbs, a global search that
   actually routes (field-aware queries for IPs/hashes/domains), an alerts indicator from the existing overview endpoint, collapsible sidebar and a
   mobile drawer.
5. **Global table handling** (style + in-container horizontal scroll) so no view can regress it, and `min-width: 0` on grid/flex children.
6. **Honesty over decoration.** No fabricated metrics; unavailable data shows “—”, never `0`; the threat map's empty states name the missing integration;
   AI hypotheses are labelled as the agent's statements.

**Backend contracts:** unchanged. The only API call added to the shell is the existing `GET /detections/overview` (alerts bell).

**Consequences.** Light-only for now (a dark theme needs a second token set and an inverted remap). Two hand-built visualisations (`viz/charts`, hunt
report) keep their own palettes, which already read correctly on light. Row-level “⋯” menus mean secondary actions need one more click.
