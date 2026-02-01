import { ByteStream } from "./bytestream";
import { LogicDoSpellCommand } from "./commands/client/logicdospellcommand";
import { Logger } from "./utility/logger";

export class CommandHandler {
  static handleCommand(id: number, stream: ByteStream): ByteStream | null {
    switch (id) {
      case 1:
        let data = LogicDoSpellCommand.decode(stream);
        LogicDoSpellCommand.execute(data);
        break;
      default:
        Logger.warn("Unhandled command of type:", id);
        return null;
    }
    return stream;
  }
}
