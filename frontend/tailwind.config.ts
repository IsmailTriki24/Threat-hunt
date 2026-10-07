import type { Config } from "tailwindcss";
export default {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: { bg: "#0d1117", panel: "#161b22", line: "#2a313c", muted: "#8b949e", accent: "#58a6ff" },
      fontSize: { xs: ["12px", "16px"], sm: ["13px", "18px"] },
    },
  },
  plugins: [],
} satisfies Config;
