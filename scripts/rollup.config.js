import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";

export default {
  input: "./src/archly.ts",
  output: [
    {
      file: "dist/archly.common.js",
      format: "cjs",
      exports: "named",
    },
    {
      file: "dist/archly.esm.js",
      format: "esm",
      exports: "named",
    },
    {
      file: "dist/archly.browser.js",
      name: "Archly",
      format: "iife",
      exports: "named",
    },
  ],
  plugins: [
    typescript({
      exclude: ["*.spec.ts", "*.test.ts"],
    }),
    commonjs(),
  ],
};
