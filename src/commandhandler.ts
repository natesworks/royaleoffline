import { ByteStream } from "./bytestream";
import { LogicSelectDeckCommand } from "./commands/client/home/decks/logicselectdeckcommand";
import { LogicSwapSpellsCommand } from "./commands/client/home/decks/logicswapspellscommand";
import { LogicChangeNameCommand } from "./commands/server/home/logicchangenamecommand";
import { Logger } from "./logger";

export class CommandHandler {
  static createCommandOfType(id: number): any {
    switch (id) {
      case 201:
        return new LogicChangeNameCommand();
      case 500:
        return new LogicSwapSpellsCommand();
      case 501:
        return new LogicSelectDeckCommand();
      default:
        Logger.warn(
          "CommandHandler::createCommandOfType",
          "No case for command of type",
          id,
        );
    }
  }

  static handleCommand(id: number, stream: ByteStream): ByteStream | null {
    let command = this.createCommandOfType(id);
    command.decode(stream);
    command.execute();
    return stream;
  }
}
