import { Logger } from "src/utility/logger";
import { ByteStream } from "../../bytestream";
import { LogicCommand } from "../../logiccommand";
import { DeckHelper } from "src/deck";
import { decks, setDecks } from "src/definitions";
import { GlobalId } from "src/globalid";
import { CSV } from "src/csv";

export class LogicSwapSpellsCommandData {
  cardOffset = 0;
  deckOffset = 0;
}

export class LogicSwapSpellsCommand {
  static commandId = 500;

  static decode(stream: ByteStream): LogicSwapSpellsCommandData {
    LogicCommand.decode(stream);

    let data = new LogicSwapSpellsCommandData();

    data.cardOffset = stream.readVInt();
    data.deckOffset = stream.readVInt();

    return data;
  }

  static execute(data: LogicSwapSpellsCommandData) {
    let spells = CSV.getSpells();

    let selectedDeck = decks.decks[decks.selected];

    selectedDeck.characters[data.deckOffset].cardId =
      spells[data.cardOffset].cardId;
    selectedDeck.characters[data.deckOffset].globalId =
      spells[data.cardOffset].globalId;
    selectedDeck.characters[data.deckOffset].level =
      spells[data.cardOffset].level;

    let old = spells[data.deckOffset];
    spells[data.deckOffset] = spells[sourceIndex];
    spells[sourceIndex] = old;

    DeckHelper.writeDecks(decks);
  }
}
