import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  root: fileURLToPath(new URL("./site", import.meta.url)),
  publicDir: "public",
  build: {
    outDir: "../dist-site",
    emptyOutDir: true,
  },
  server: { host: "127.0.0.1", port: 4174, strictPort: true },
  preview: { host: "127.0.0.1", port: 4174, strictPort: true },
});
