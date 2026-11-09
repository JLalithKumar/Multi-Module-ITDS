import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        abyss: "#0B0F17",
        panel: "#111827",
        line: "#1E293B",
        cyanx: "#3B82F6",    // Executive Royal Cobalt Blue (primary)
        mintx: "#10B981",    // Crisp Emerald
        amberx: "#F59E0B",   // Refined Warning Amber
        dangerx: "#EF4444",  // Crisp Emergency Red
      },
      boxShadow: {
        glow: "0 0 35px rgba(59, 130, 246, 0.12)",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
      },
    },
  },
  plugins: [],
} satisfies Config;
