import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  server: {
    port: 5173,
    proxy: {
      "/ui": { target: "http://127.0.0.1:17845", changeOrigin: true },
      "/support": { target: "http://127.0.0.1:17845", changeOrigin: true },
      "/debug": { target: "http://127.0.0.1:17845", changeOrigin: true },
      "/health": { target: "http://127.0.0.1:17845", changeOrigin: true },
      "/sessions": { target: "http://127.0.0.1:17845", changeOrigin: true },
      "/roots": { target: "http://127.0.0.1:17845", changeOrigin: true },
    },
  },
});
