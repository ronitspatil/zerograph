import type { Config } from "tailwindcss";
export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        border: "#243143",
        background: "#0a101b",
        foreground: "#e5edf8",
        primary: "#80e8ce",
      },
    },
  },
  plugins: [],
} satisfies Config;
