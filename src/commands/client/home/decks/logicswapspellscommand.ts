import { ByteStream } from "src/bytestream";
import { LogicCommand } from "src/logiccommand";
import { userdata } from "src/definitions";
import { CSV } from "src/csv";
import { Logger } from "src/utility/logger";

export class LogicSwapSpellsCommandthis {
  cardOffset = 0;
  deckOffset = 0;
}

export class LogicSwapSpellsCommand {
  static commandId = 500;

  cardOffset = 0;
  deckOffset = 0;

  decode(stream: ByteStream) {
    LogicCommand.decode(stream);

    this.cardOffset = stream.readVInt();
    this.deckOffset = stream.readVInt();
  }

  execute() {
    const spells = CSV.getSpells();
    const decks = userdata.decks;

    let selectedDeck = decks.decks[decks.selected];

    selectedDeck.characters[this.deckOffset].cardId =
      spells[this.cardOffset].cardId;
    selectedDeck.characters[this.deckOffset].globalId =
      spells[this.cardOffset].globalId;
    selectedDeck.characters[this.deckOffset].level =
      spells[this.cardOffset].level;

    let old = spells[this.deckOffset];
    spells[this.deckOffset] = spells[this.cardOffset];
    spells[this.cardOffset] = old;

    userdata.write();
  }
}
