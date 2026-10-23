import type { Config } from "tailwindcss";
import colors from "tailwindcss/colors";

/** Design tokens live in `src/app/globals.css` as CSS variables (space-separated RGB so opacity modifiers work: `bg-accent/10`).
 *  This file only maps them to utility names. See docs/design-system.md. */
const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

/** The codebase was written against a dark theme and uses palette utilities directly (`text-red-300` = readable-on-dark, `bg-red-900/50` = chip
 *  background on dark). Rather than touch ~1,000 call sites, each hue's scale is remapped for the light theme: light shades (readable on dark) become
 *  dark text tones, dark shades (chip backgrounds) become light tints, and mid shades (bars, dots, borders) are unchanged. New code should prefer the
 *  semantic tokens (`text-ink`, `text-sev-high`, `bg-sev-high-bg`, ...). */
type Scale = Record<string, string>;
const remap = (s: Scale): Scale => ({
  50: s[800], 100: s[800], 200: s[700], 300: s[700], 400: s[600], 500: s[500], 600: s[600], 700: s[700],
  800: s[100], 900: s[200], 950: s[50],
});
const slate = colors.slate as Scale;
const slateLight: Scale = {
  50: slate[900], 100: slate[900], 200: slate[800], 300: slate[700], 400: slate[600], 500: slate[500], 600: slate[500], 700: slate[700],
  800: slate[200], 900: slate[100], 950: slate[50],
};

export default {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    screens: { sm: "640px", md: "768px", lg: "1024px", xl: "1280px", "2xl": "1536px" },
    extend: {
      colors: {
        bg: token("bg"), panel: token("panel"), subtle: token("subtle"), line: token("line"), "line-strong": token("line-strong"),
        ink: token("ink"), "ink-2": token("ink-2"), muted: token("muted"),
        accent: { DEFAULT: token("accent"), strong: token("accent-strong"), soft: token("accent-soft"), brand: token("accent-brand") },
        ai: token("accent"),
        sev: {
          critical: token("sev-critical"), "critical-bg": token("sev-critical-bg"), high: token("sev-high"), "high-bg": token("sev-high-bg"),
          medium: token("sev-medium"), "medium-bg": token("sev-medium-bg"), low: token("sev-low"), "low-bg": token("sev-low-bg"),
          info: token("sev-info"), "info-bg": token("sev-info-bg"), ok: token("sev-ok"), "ok-bg": token("sev-ok-bg"),
        },
        slate: slateLight,
        red: remap(colors.red as Scale), orange: remap(colors.orange as Scale), amber: remap(colors.amber as Scale), yellow: remap(colors.yellow as Scale),
        green: remap(colors.green as Scale), emerald: remap(colors.emerald as Scale), sky: remap(colors.sky as Scale), blue: remap(colors.blue as Scale),
        cyan: remap(colors.cyan as Scale), violet: remap(colors.violet as Scale), purple: remap(colors.purple as Scale),
      },
      fontFamily: {
        display: ['"Bricolage Grotesque Variable"', '"Inter Variable"', "ui-sans-serif", "system-ui", "sans-serif"],
        sans: ['"Inter Variable"', "Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      fontSize: { xs: ["12px", "16px"], sm: ["13px", "18px"], base: ["14px", "20px"], lg: ["16px", "22px"], xl: ["18px", "24px"], "2xl": ["22px", "28px"], "3xl": ["28px", "34px"] },
      borderRadius: { sm: "4px", DEFAULT: "6px", md: "8px", lg: "10px", xl: "14px" },
      boxShadow: {
        xs: "0 1px 1px rgb(16 24 40 / .04)", card: "0 1px 2px rgb(16 24 40 / .05), 0 0 0 1px rgb(var(--line) / 1)",
        pop: "0 8px 24px rgb(16 24 40 / .12), 0 0 0 1px rgb(var(--line) / 1)", drawer: "-12px 0 32px rgb(16 24 40 / .12)",
      },
      transitionDuration: { fast: "120ms", base: "180ms", slow: "220ms" },
      transitionTimingFunction: { out: "cubic-bezier(.2,.8,.2,1)" },
      keyframes: {
        feedIn: { from: { opacity: "0", transform: "translateY(4px)" }, to: { opacity: "1", transform: "none" } },
        fadeIn: { from: { opacity: "0" }, to: { opacity: "1" } },
        slideIn: { from: { transform: "translateX(24px)", opacity: "0" }, to: { transform: "none", opacity: "1" } },
        popIn: { from: { opacity: "0", transform: "translateY(6px) scale(.98)" }, to: { opacity: "1", transform: "none" } },
        pulseRing: { "0%": { boxShadow: "0 0 0 0 rgb(var(--accent) / .45)" }, "70%": { boxShadow: "0 0 0 8px rgb(var(--accent) / 0)" }, "100%": { boxShadow: "0 0 0 0 rgb(var(--accent) / 0)" } },
        scan: { from: { transform: "translateX(-100%)" }, to: { transform: "translateX(260%)" } },
        spinSlow: { to: { transform: "rotate(360deg)" } },
        dotBounce: { "0%,80%,100%": { transform: "scale(.55)", opacity: ".35" }, "40%": { transform: "scale(1)", opacity: "1" } },
        blink: { "0%,49%": { opacity: "1" }, "50%,100%": { opacity: "0" } },
        shimmer: { from: { backgroundPosition: "200% 0" }, to: { backgroundPosition: "-200% 0" } },
        skeleton: { "0%,100%": { opacity: ".55" }, "50%": { opacity: "1" } },
        floaty: { "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-3px)" } },
        growX: { from: { transform: "scaleX(0)" }, to: { transform: "scaleX(1)" } },
        windowIn: { from: { opacity: "0", transform: "translateY(8px) scale(.985)" }, to: { opacity: "1", transform: "none" } },
        reveal: { from: { transform: "translateY(108%)" }, to: { transform: "none" } },
        riseIn: { from: { opacity: "0", transform: "translateY(16px) scale(.985)" }, to: { opacity: "1", transform: "none" } },
        shake: { "0%,100%": { transform: "none" }, "20%": { transform: "translateX(-7px)" }, "40%": { transform: "translateX(6px)" }, "60%": { transform: "translateX(-4px)" }, "80%": { transform: "translateX(2px)" } },
        flash: { "0%": { backgroundColor: "rgb(var(--accent) / .18)" }, "100%": { backgroundColor: "transparent" } },
      },
      animation: {
        "feed-in": "feedIn .18s ease-out both", "fade-in": "fadeIn .15s ease-out both", "slide-in": "slideIn .2s cubic-bezier(.2,.8,.2,1) both",
        "pop-in": "popIn .16s ease-out both", "pulse-ring": "pulseRing 1.8s ease-out infinite", scan: "scan 1.4s linear infinite",
        "spin-slow": "spinSlow 5s linear infinite", "dot-bounce": "dotBounce 1.2s ease-in-out infinite", blink: "blink 1s steps(1) infinite",
        shimmer: "shimmer 3s linear infinite", skeleton: "skeleton 1.4s ease-in-out infinite", "dot-in": "popIn .2s ease-out backwards",
        floaty: "floaty 3s ease-in-out infinite", flash: "flash 1.2s ease-out both", "grow-x": "growX .5s cubic-bezier(.2,.8,.2,1) backwards",
        "window-in": "windowIn .2s cubic-bezier(.2,.8,.2,1) both",
        "scene-in": "fadeIn 1.8s ease-out both", reveal: "reveal .95s cubic-bezier(.2,.8,.2,1) both",
        "rise-in": "riseIn .85s cubic-bezier(.2,.8,.2,1) .5s both", shake: "shake .38s cubic-bezier(.36,.07,.19,.97) both",
      },
    },
  },
  plugins: [],
} satisfies Config;
