import * as frida from "frida";
import fs from "fs";

async function main() {
  const device = await frida.getUsbDevice();
  const session = await device.attach("Gadget");

  const source = fs.readFileSync("script.js", "utf8");
  const script = await session.createScript(source);

  script.message.connect((message, data) => {
    // thanks Hallo
    if (message.type === "error") {
      console.error(message.stack);
    }
  });

  await script.load();
}

main();
