const path = require("path");
const esbuild = require("esbuild");

const args = process.argv.slice(2);
const argMap = {};
args.forEach((arg) => {
  const [key, value] = arg.split("=");
  argMap[key.replace(/^--/, "")] = value;
});

const gmv = argMap.gmv;
let devicePath = argMap.device === "android" ? "android/arm" : "ios";

esbuild
  .build({
    entryPoints: ["src/init.ts"],
    bundle: true,
    outfile: "script.js",
    plugins: [
      {
        name: "get-correct-ver",
        setup(build) {
          build.onResolve({ filter: /^version$/ }, (args) => {
            return {
              path: path.resolve(
                __dirname,
                `src/version/v${gmv}/${devicePath}/version.ts`,
              ),
              namespace: "file",
            };
          });

          build.onResolve({ filter: /^OwnHomeDataMessage$/ }, (args) => {
            return {
              path: path.resolve(
                __dirname,
                `src/packets/server/ownhomedatamessage/v${gmv}/ownhomedatamessage.ts`,
              ),
              namespace: "file",
            };
          });
        },
      },
    ],
  })
  .catch(() => process.exit(1));
