import { DeckHelper } from "./deck.js";
import { base, load, setBase } from "./definitions.js";
import { installHooks } from "./mainHooks.js";
import { Offsets } from "./offsets.js";
import { isAndroid } from "./platform.js";
import { getDocumentsDirectory } from "./util.js";
import { Logger } from "./utility/logger.js";

Logger.info("Clash Royale Offline created by Natesworks");
let library = isAndroid ? "libg.so" : "laser";
setBase(Process.getModuleByName(library).base);
load();
installHooks();
Logger.info("Succesfully installed hooks");
