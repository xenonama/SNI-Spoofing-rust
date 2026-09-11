export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0A0C10",
        surface: "#12161D",
        card: "#181C24",
        "card-edge": "#252B36",
        accent: "#00B4D8",
        success: "#06D6A0",
        danger: "#EF476F",
        warning: "#FFD166",
        muted: "#8B95A7",
        faint: "#5C6575",
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI Variable", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "Consolas", "monospace"],
      },
      borderRadius: { xl: "12px", "2xl": "16px" },
      boxShadow: {
        glow: "0 0 24px rgba(0, 180, 216, 0.15)",
        "glow-lg": "0 0 40px rgba(0, 180, 216, 0.25)",
      },
    },
  },
  plugins: [],
};
