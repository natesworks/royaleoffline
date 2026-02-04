import { ByteStream } from "./bytestream";
import { Character } from "./character";
import { CSV } from "./csv";
import { access, documentsDirectory, unlink } from "./definitions";
import { Logger } from "./utility/logger";

export class Deck {
  characters: Character[];

  constructor(characters: Character[]) {
    this.characters = characters;
  }
}

export class Decks {
  decks: Deck[];
  selected: number;

  constructor(decks: Deck[] = [], selected: number = 0) {
    this.decks = decks;
    this.selected = selected;
  }
}

export class DeckHelper {
  static readDecks(): Decks {
    const result: Decks = new Decks();
    const path = documentsDirectory + "/decks.bin";

    if (access(Memory.allocUtf8String(path), 0) === -1) {
      this.writeDefaultDecks();
    }

    const data = File.readAllBytes(path);
    const stream = new ByteStream(Array.from(new Uint8Array(data)));

    result.selected = stream.readByte();
    const deckCount = stream.readByte();

    for (let i = 0; i < deckCount; i++) {
      const characters: Character[] = [];
      let characterCount = stream.readInt();

      if (characterCount != 8) {
        Logger.error("Unsupported character count");
        throw new Error();
      }

      for (let j = 0; j < 8; j++) {
        const globalId = stream.readInt();
        const cardId = stream.readInt();
        const level = stream.readInt();
        characters.push(new Character(globalId, cardId, level));
      }

      result.decks.push(new Deck(characters));
    }

    return result;
  }

  static writeDecks(decks: Decks) {
    const path = documentsDirectory + "/decks.bin";
    unlink(Memory.allocUtf8String(path));

    const stream = new ByteStream([]);

    stream.writeByte(decks.selected);
    stream.writeByte(decks.decks.length);

    for (let i = 0; i < decks.decks.length; i++) {
      const deck = decks.decks[i];
      stream.writeInt(deck.characters.length);
      for (let j = 0; j < deck.characters.length; j++) {
        const character = deck.characters[j];
        stream.writeInt(character.globalId);
        stream.writeInt(character.cardId);
        stream.writeInt(character.level);
      }
    }

    File.writeAllBytes(path, stream.payload);
  }

  static writeDefaultDecks() {
    Logger.debug("Writing default decks");

    const path = documentsDirectory + "/decks.bin";
    unlink(Memory.allocUtf8String(path));

    const stream = new ByteStream([]);
    const characters = CSV.getSpells();

    stream.writeByte(0);
    stream.writeByte(5);

    for (let i = 0; i < 5; i++) {
      stream.writeInt(8);
      for (let j = 0; j < 8; j++) {
        const character = characters[j];
        stream.writeInt(character.globalId);
        stream.writeInt(character.cardId);
        stream.writeInt(character.level);
      }
    }

    File.writeAllBytes(path, stream.payload);
  }
}
