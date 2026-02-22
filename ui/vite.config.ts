import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  server: {
    port: 5173,
    proxy: {
      "/ui/state": { target: "http://127.0.0.1:17845", changeOrigin: true },
      "/ui/sessions": { target: "http://127.0.0.1:17845", changeOrigin: true },
      "/debug": { target: "http://127.0.0.1:17845", changeOrigin: true },
    },
  },
});
