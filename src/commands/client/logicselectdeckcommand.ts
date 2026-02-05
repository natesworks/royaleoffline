import { Logger } from "src/utility/logger";
import { ByteStream } from "../../bytestream";
import { LogicCommand } from "../../logiccommand";
import { DeckHelper } from "src/deck";
import { userdata } from "src/definitions";
import { UserData } from "src/userdata";

export class LogicSelectDeckCommand {
  static commandId = 501;

  static decode(stream: ByteStream): number {
    LogicCommand.decode(stream);

    let deckIndex = stream.readVInt();

    return deckIndex;
  }

  static execute(deckIndex: number) {
    const decks = userdata.decks;

    Logger.debug("Switching to deck", deckIndex);

    decks.selected = deckIndex;
    userdata.write();
  }
}
