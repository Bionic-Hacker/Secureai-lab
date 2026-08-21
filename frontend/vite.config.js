import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const target = process.env.VITE_PROXY_TARGET || "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    strictPort: true,
    // Bind-mounted files on Windows don't emit inotify events to Linux
    // containers, so hot reload needs polling.
    watch: { usePolling: true, interval: 300 },
    proxy: {
      "/api": { target, changeOrigin: true },
    },
  },
});
