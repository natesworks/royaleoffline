import { load } from "./definitions";
import { installHooks } from "./mainHooks";
import { Logger } from "./logger";

load();
installHooks();
Logger.info("Clash Royale Offline created by Natesworks");
