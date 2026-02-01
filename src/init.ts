import { base, load, setBase } from "./definitions.js";
import { installHooks } from "./mainHooks.js";
import { Offsets } from "./offsets.js";
import { isAndroid } from "./platform.js";
import { Logger } from "./utility/logger.js";

let library = isAndroid ? "libg.so" : "laser";
setBase(Process.getModuleByName(library).base);
load();
Logger.info("Clash Royale Offline created by Natesworks");
Logger.info("Powered by Frida");
Logger.info("Running on", isAndroid ? "Android" : "iOS");
Logger.verbose(`${library} loaded at: ${base}`);
installHooks();
Logger.info("Succesfully installed hooks");
