import devServer from "@hono/vite-dev-server";
import adapter from "@hono/vite-dev-server/cloudflare";
import { defineConfig } from "vite";

export default defineConfig(({ command }) => ({
  plugins:
    command === "serve"
      ? [
          devServer({
            entry: "src/index.tsx",
            adapter,
          }),
        ]
      : [],
  build: {
    ssr: true,
    outDir: "dist",
    emptyOutDir: true,
    minify: true,
    rollupOptions: {
      input: "./src/worker.ts",
      output: {
        entryFileNames: "_worker.js",
        format: "es",
      },
    },
    target: "esnext",
  },
  ssr: {
    noExternal: true,
  },
}));
