import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  build: {
    target: "es2022",
    sourcemap: false,
    cssCodeSplit: true,
    manifest: true,
    rollupOptions: {
      output: {
        entryFileNames: "assets/panel-[hash].js",
        chunkFileNames: "assets/chunk-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]"
      }
    }
  },
  server: {
    strictPort: true,
    port: 4173
  }
});
