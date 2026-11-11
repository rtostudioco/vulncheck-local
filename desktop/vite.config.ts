import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed dev port and no cache-busting headers.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  // The desktop UI uses plain CSS tokens (no framework). Pin an empty, inline
  // PostCSS config so Vite never walks up into a parent project and picks up
  // its postcss/tailwind config (which would crash the standalone build).
  css: {
    postcss: { plugins: [] },
  },
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    target: "es2021",
    outDir: "dist",
  },
});
