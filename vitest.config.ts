import { readFile } from "node:fs/promises";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    {
      name: "sql-as-text",
      enforce: "pre",
      async load(id) {
        if (!id.endsWith(".sql")) return null;
        const content = await readFile(id, "utf8");
        return `export default ${JSON.stringify(content)};`;
      },
    },
  ],
  resolve: {
    // Prefer .ts source files over pre-compiled .js counterparts when both exist.
    extensions: [".ts", ".tsx", ".mts", ".js", ".jsx", ".mjs", ".json"],
  },
  test: {
    include: ["tests/**/*.test.ts"],
  },
});
