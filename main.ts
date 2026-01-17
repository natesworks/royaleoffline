import * as frida from "frida";
import fs from "fs";
import path from "path";

const trackers = new Map();

async function main() {
  const device = await frida.getUsbDevice();
  const session = await device.attach("Gadget");

  const source = fs.readFileSync("script.js", "utf8");
  const script = await session.createScript(source);

  await script.load();
}

main();
