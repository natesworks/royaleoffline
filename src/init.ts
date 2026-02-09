import { load, setBase } from "./definitions.js";
import { installHooks } from "./mainHooks.js";
import { isAndroid } from "./platform.js";
import { Logger } from "./utility/logger.js";

let library = isAndroid ? "libg.so" : "laser";
setBase(Process.getModuleByName(library).base);
load();
installHooks();
Logger.info("Clash Royale Offline created by Natesworks");
