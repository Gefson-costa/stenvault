import { defineConfig } from "vitest/config";
import path from "path";

const root = path.resolve(import.meta.dirname);

export default defineConfig({
  root,
  resolve: {
    alias: {
      "@": path.resolve(root, "apps", "web", "src"),
      "@shared": path.resolve(root, "packages", "shared", "src"),
      "@stenvault/shared": path.resolve(root, "packages", "shared", "src"),
    },
  },
  test: {
    environment: "happy-dom",
    environmentMatchGlobs: [
      ["apps/web/**/*.test.{ts,tsx}", "happy-dom"],
      ["apps/web/**/*.spec.{ts,tsx}", "happy-dom"],
      ["packages/shared/**/*.test.ts", "node"],
    ],
    include: [
      "apps/web/**/*.test.ts",
      "apps/web/**/*.test.tsx",
      "apps/web/**/*.spec.ts",
      "apps/web/**/*.spec.tsx",
      "packages/shared/**/*.test.ts",
      "packages/shared/**/*.spec.ts",
    ],
    setupFiles: ["./apps/web/vitest-setup.ts"],
    globals: true,
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
