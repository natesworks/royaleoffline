const esbuild = require("esbuild");

esbuild
  .build({
    entryPoints: ["src/init.ts"],
    bundle: true,
    outfile: "script.js",
  })
  .catch(() => process.exit(1));
