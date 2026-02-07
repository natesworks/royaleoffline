import { Logger } from "src/utility/logger";
import { ByteStream } from "src/bytestream";
import { LogicCommand } from "src/logiccommand";
import { userdata } from "src/definitions";

export class LogicSelectDeckCommand {
  static commandId = 501;

  deckIndex = 0;

  decode(stream: ByteStream) {
    LogicCommand.decode(stream);

    this.deckIndex = stream.readVInt();
  }

  execute() {
    const decks = userdata.decks;

    Logger.debug("Switching to deck", this.deckIndex);

    decks.selected = this.deckIndex;
    userdata.write();
  }
}
