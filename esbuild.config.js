const path = require("path");
const esbuild = require("esbuild");

const args = process.argv.slice(2);
const argMap = {};
args.forEach((arg) => {
  const [key, value] = arg.split("=");
  argMap[key.replace(/^--/, "")] = value;
});

const arch = argMap.arch;
let devicePath = argMap.device == "android" ? "android/" + arch : "ios";

esbuild
  .build({
    entryPoints: ["src/init.ts"],
    bundle: true,
    outfile: "script.js",
    plugins: [
      {
        name: "get-correct-ver",
        setup(build) {
          build.onResolve({ filter: /^offsets$/ }, (args) => {
            return {
              path: path.resolve(
                __dirname,
                `src/offsets/${devicePath}/offsets.ts`,
              ),
              namespace: "file",
            };
          });
        },
      },
    ],
  })
  .catch(() => process.exit(1));
