import { ByteStream } from "../../bytestream";
import { LogicCommand } from "../../logiccommand";
import { userdata } from "src/definitions";
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
    const spells = CSV.getSpells();
    const decks = userdata.decks;

    let selectedDeck = decks.decks[decks.selected];

    selectedDeck.characters[data.deckOffset].cardId =
      spells[data.cardOffset].cardId;
    selectedDeck.characters[data.deckOffset].globalId =
      spells[data.cardOffset].globalId;
    selectedDeck.characters[data.deckOffset].level =
      spells[data.cardOffset].level;

    let old = spells[data.deckOffset];
    spells[data.deckOffset] = spells[data.cardOffset];
    spells[data.cardOffset] = old;

    userdata.write();
  }
}
