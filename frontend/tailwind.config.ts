import type { Config } from "tailwindcss";
export default {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: { bg: "#0d1117", panel: "#161b22", line: "#2a313c", muted: "#8b949e", accent: "#58a6ff", ai: "#a78bfa" },
      fontSize: { xs: ["12px", "16px"], sm: ["13px", "18px"] },
      keyframes: {
        feedIn: { from: { opacity: "0", transform: "translateY(12px) scale(.985)" }, to: { opacity: "1", transform: "none" } },
        pulseRing: { "0%": { boxShadow: "0 0 0 0 rgba(167,139,250,.55)" }, "70%": { boxShadow: "0 0 0 10px rgba(167,139,250,0)" }, "100%": { boxShadow: "0 0 0 0 rgba(167,139,250,0)" } },
        scan: { from: { transform: "translateX(-100%)" }, to: { transform: "translateX(260%)" } },
        spinSlow: { to: { transform: "rotate(360deg)" } },
        dotBounce: { "0%,80%,100%": { transform: "scale(.55)", opacity: ".35" }, "40%": { transform: "scale(1)", opacity: "1" } },
        blink: { "0%,49%": { opacity: "1" }, "50%,100%": { opacity: "0" } },
        shimmer: { from: { backgroundPosition: "200% 0" }, to: { backgroundPosition: "-200% 0" } },
        popIn: { "0%": { opacity: "0", transform: "scale(.7)" }, "70%": { transform: "scale(1.08)" }, "100%": { opacity: "1", transform: "scale(1)" } },
        floaty: { "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-3px)" } },
        flash: { "0%": { backgroundColor: "rgba(167,139,250,.28)" }, "100%": { backgroundColor: "transparent" } },
      },
      animation: {
        "feed-in": "feedIn .45s cubic-bezier(.2,.8,.2,1) both",
        "pulse-ring": "pulseRing 1.6s ease-out infinite",
        scan: "scan 1.4s linear infinite",
        "spin-slow": "spinSlow 5s linear infinite",
        "dot-bounce": "dotBounce 1.2s ease-in-out infinite",
        blink: "blink 1s steps(1) infinite",
        shimmer: "shimmer 3s linear infinite",
        "pop-in": "popIn .4s cubic-bezier(.2,.9,.3,1.3) both",
        floaty: "floaty 3s ease-in-out infinite",
        flash: "flash 1.2s ease-out both",
      },
    },
  },
  plugins: [],
} satisfies Config;
