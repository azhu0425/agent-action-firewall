import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The API is proxied under /api in dev (Vite) and in Docker (nginx), so the browser only ever
// talks to one origin and the API needs no CORS. 127.0.0.1, not localhost: Node resolves
// localhost to ::1 first on Windows, where uvicorn is not listening.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", rewrite: (path) => path.replace(/^\/api/, "") },
    },
    // The Corpus view imports the human-owned eval corpus from the repo root at build time.
    fs: { allow: [".."] },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    css: false,
  },
});
