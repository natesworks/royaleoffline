import { Logger } from "src/utility/logger";
import { ByteStream } from "../../bytestream";
import { LogicCommand } from "../../logiccommand";
import { DeckHelper } from "src/deck";
import { decks } from "src/definitions";

export class LogicSelectDeckCommand {
  static commandId = 501;

  static decode(stream: ByteStream): number {
    LogicCommand.decode(stream);

    let deckIndex = stream.readVInt();

    return deckIndex;
  }

  static execute(deckIndex: number) {
    Logger.debug("Switching to deck", deckIndex);
    decks.selected = deckIndex;
    DeckHelper.writeDecks(decks);
  }
}
