# Design system

The UI is a **light, information-dense enterprise theme** built on Tailwind, with a purple identity (`#7568E9`). Everything below lives in
code; this page is the map. Decision record: ADR 0017.

## Tokens (`frontend/src/app/globals.css`, mapped in `tailwind.config.ts`)
Tokens are CSS variables holding space-separated RGB so opacity modifiers work (`bg-accent/10`). Change a value once; the whole product follows.

| Group | Tokens | Notes |
|---|---|---|
| Surfaces | `bg` (canvas), `panel` (cards, inputs), `subtle` (table headers, hover), `line`, `line-strong` | Cards are white on a `#F4F5FA` canvas with a 1 px border and a hairline shadow. |
| Text | `ink` (primary), `ink-2`, `muted` | Contrast on white: 16:1 / 9:1 / 6:1. Never use `muted` for anything a user must act on. |
| Brand | `accent-brand` `#7568E9` (graphics, focus ring, fills), `accent` `#6457D8` (text, links, filled buttons), `accent-strong` (hover), `accent-soft` (tints) | `accent` is a deliberate half-step darker than the brand colour: it is the lightest purple that still gives 5.4:1 on white and 4.75:1 on `accent-soft` (WCAG AA for 12–13 px text). |
| Severity | `sev-critical|high|medium|low|info|ok` (text) and `-bg` (tint) | One vocabulary for severity, status and health everywhere. |
| Type | Inter Variable (self-hosted via `@fontsource-variable/inter`, no network), JetBrains Mono → system mono for indicators | Scale: 12 / 13 (default) / 14 / 16 / 18 / 22 / 28 px. |
| Shape | radii 4 / 6 / 8 / 10 / 14, shadows `xs`, `card`, `pop`, `drawer` | |
| Motion | 120 / 180 / 220 ms, `ease-out`; every animation is disabled under `prefers-reduced-motion` | Continuous motion only while an AI run is active or when the user turns on arc animation. |
| Layout | sidebar 232 px (60 px collapsed), header 52 px, content max 1680 px, breakpoints 640 / 768 / 1024 / 1280 / 1536 | |

### Severity is never colour alone
`SeverityBadge` (`components/ui/severity.tsx`) renders an icon **shape** (shield-alert, triangle, circle-alert, dot, info, check) plus the **text label**
plus colour. `toLevel()` maps strings (`CRITICAL`, `degraded`, …) and 0–100 event severity (≥80 critical, ≥60 high, ≥40 medium, ≥20 low) onto the
same six levels. Case severity, case status, detection status, hunt status, verdicts, ATT&CK confidence, provider health and event severity all use it.
Confidence is *not* a severity and is drawn in the brand colour.

### Legacy palette classes
The codebase was written for a dark theme and uses Tailwind palette utilities directly (`text-red-300`, `bg-red-900/50`). Rather than rewrite ~1,000 call
sites, `tailwind.config.ts` **remaps each hue's scale** for the light theme: the shades that were readable on dark (50–300) become dark text tones, 400
becomes the 700 tone, the dark chip backgrounds (800–900) become light tints, and mid shades (bars, dots, borders) are unchanged. New code should use the
semantic tokens (`text-sev-high`, `bg-sev-high-bg`, `text-ink`) instead. A dark theme would be a second set of token values plus an inverted remap.

## Components (`frontend/src/components/ui/`)
| Component | Use |
|---|---|
| `PageHeader`, `Section` | Every page starts with a `PageHeader` (title, one line of purpose, primary actions). `Section` is a titled card. `flush` removes the margin inside flex/grid parents. |
| `KpiCard` | One headline number with context. `href` makes it a drill-down; `loading`, `unavailable` (“—”) and a real `0` are three distinct states. `compact` for pages where a map or table must stay the focus. |
| `SeverityBadge`, `SeverityDot`, `LevelBadge`, `StatusBadge`, `HealthBadge` | See above. |
| `Tabs` | Accessible tab strip with arrow-key navigation and counts. Replaces five hand-rolled tab implementations. |
| `EmptyState`, `Loading`, `Skeleton` | Say what is empty and the next step; skeleton rows with a polite “Loading…”. |
| `Modal`, `Drawer`, `ConfirmDialog`, `useConfirm` | One overlay behaviour: Escape closes, focus moves in and is trapped, scroll is locked, focus returns to the opener, backdrop click closes. `useConfirm` replaced every `window.confirm()`; the primary button names the action (“Delete feed”), never “OK”. |
| `ActionMenu` | Overflow (“⋯”) menu for secondary row actions; arrow keys, Escape, fixed positioning so scrolling tables never clip it. |
| `ToastProvider` / `useToast` | Success toasts auto-dismiss (polite); errors persist (assertive). Safe no-op outside a provider. |
| `CopyValue`, `CopyButton` | Indicators are monospace and one click from the clipboard, with an announced “Copied”. |
| `BarList`, `BackLink`, `Tooltip` | Ranked lists with printed values; consistent “← List” link on detail pages; hover/focus tooltips (used for icon-only navigation). |

## Conventions
* **Tables.** Any `<table>` inside the app shell is styled globally (header, row hover, borders, rounded card). It scrolls inside its own container
  instead of making the page scroll sideways (`main :has(> table)`), and grid/flex children may shrink (`min-width: 0`). Use `class="raw"` to opt out
  (the Events results table does, because it needs a sticky header inside `.table-wrap`).
* **States.** Every data view handles loading (`Loading`), error (inline alert with the server's message and a retry where useful), empty
  (`EmptyState` with guidance) and success (toast). Never show `0` for data that failed to load.
* **Destructive actions** go through `useConfirm`. **Secondary row actions** go into `ActionMenu`; a row keeps at most two visible buttons.
* **Forms.** Visible labels, hints under the field, inline errors, buttons disabled while a request is in flight.
* **Provenance.** External intelligence, observed activity and correlations keep distinct colours and wording; AI output is labelled as AI-stated
  (“supported” means the cited events back it, not that it is a verdict).

## Shell
`components/shell.tsx` + `lib/nav.ts` (single source of truth for navigation, breadcrumbs and the route test). Grouped sidebar (Investigate ·
Intelligence · Detect & respond · Manage), collapsible with the choice remembered, off-canvas drawer below 1024 px, breadcrumb, a **working global
search** (IP, CIDR, hash, domain → field-aware event search; optional threat-intel lookup; `Ctrl/⌘+K`), an alerts indicator backed by the real open-alert
count, tenant switcher and user menu, and a skip-to-content link.

## Accessibility (WCAG 2.2 AA targets)
* Visible `:focus-visible` ring on everything; focus management in overlays; skip link; semantic landmarks with unique names; one `h1` per page.
* Contrast: tokens are chosen to pass AA (see above); axe-core reports no `color-contrast` violations on any route.
* Touch/click targets ≥ 24 px; icons are decorative (`aria-hidden`) or labelled; accessible names contain their visible text.
* Status announcements: toasts and “Loading…” use `role=status`; errors use `role=alert`.
* Reduced motion: all animation is neutralised by `prefers-reduced-motion`.

## Verifying a change
```bash
cd frontend && npx tsc --noEmit && npx eslint src && npx vitest run     # types, lint, 289 tests
```
Visual/responsive/a11y checks used for this redesign (run against the live stack): headless Chromium screenshots of every route at 1440, 820 and
390 px; a script that fails if any route scrolls the page horizontally; axe-core (`wcag2a/aa`, `wcag21aa`, `wcag22aa`, best-practice) on all 19
routes. Sign in by routing `/api/v1/auth/refresh` to a token minted for a dev user.
