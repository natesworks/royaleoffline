import { base, load, setBase } from "./definitions.js";
import { installHooks } from "./mainHooks.js";
import { Offsets } from "./offsets.js";
import { isAndroid } from "./platform.js";
import { Logger } from "./utility/logger.js";

let library = isAndroid ? "libg.so" : "laser";
setBase(Process.getModuleByName(library).base);
load();
Logger.info("Running on", isAndroid ? "Android" : "iOS");
Logger.verbose(`${library} loaded at: ${base}`);
Memory.patchCode(
  base.add(Offsets.CreateMessageByTypeCMP),
  Process.pageSize,
  (code) => {
    const pcWriter = new X86Writer(code);
    pcWriter.putNop();
    pcWriter.putJmpAddress(base.add(Offsets.CreateMessageByTypeJumpAddress));
    pcWriter.flush();
  },
);
installHooks();
