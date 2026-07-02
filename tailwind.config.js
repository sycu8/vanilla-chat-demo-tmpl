/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./public/index.html",
    "./public/static/**/*.js",
    "./index.html",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      colors: {
        forge: {
          bg: "#0a0e17",
          surface: "#111827",
          card: "#1a2332",
          border: "#1e293b",
          accent: "#00ff88",
          accent2: "#38bdf8",
          danger: "#ef4444",
          warn: "#eab308",
          safe: "#22c55e",
          muted: "#64748b",
          text: "#e2e8f0",
        },
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scanLine 2s linear infinite",
        glow: "glow 2s ease-in-out infinite alternate",
      },
      keyframes: {
        scanLine: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        glow: {
          "0%": { boxShadow: "0 0 5px #00ff8844, 0 0 10px #00ff8822" },
          "100%": { boxShadow: "0 0 15px #00ff8866, 0 0 30px #00ff8833" },
        },
      },
      boxShadow: {
        forge: "0 0 20px rgba(0, 255, 136, 0.15)",
        "forge-lg": "0 4px 30px rgba(0, 0, 0, 0.5)",
      },
    },
  },
  plugins: [],
};
