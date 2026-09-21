import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: [
      "**/node_modules/**",
      "**/dist/**",
      "tests/browser/**",
      // This file is an intentional node:test executable invoked by
      // `npm run test:external-ti`; loading it in Vitest creates a false
      // "No test suite found" failure after its node:test assertions pass.
      "tests/external-ti-presentation.test.mjs",
    ],
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});
