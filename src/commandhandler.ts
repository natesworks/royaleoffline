import { ByteStream } from "./bytestream";
import { LogicSelectDeckCommand } from "./commands/client/logicselectdeckcommand";
import {
  LogicSwapSpellsCommand,
  LogicSwapSpellsCommandData,
} from "./commands/client/logicswapspellscommand";
import { Logger } from "./utility/logger";

export class CommandHandler {
  static handleCommand(id: number, stream: ByteStream): ByteStream | null {
    switch (id) {
      case 500: {
        let data = LogicSwapSpellsCommand.decode(stream);
        LogicSwapSpellsCommand.execute(data);
        break;
      }
      case 501: {
        let data = LogicSelectDeckCommand.decode(stream);
        LogicSelectDeckCommand.execute(data);
        break;
      }
      default:
        Logger.warn("Unhandled command of type:", id);
        return null;
    }
    return stream;
  }
}
