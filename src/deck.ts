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
  static readDecks(stream: ByteStream): Decks {
    const result: Decks = new Decks();

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

  static writeDecks(stream: ByteStream, decks: Decks) {
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
  }

  static writeDefaultDecks(stream: ByteStream) {
    Logger.debug("Writing default decks");

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
  }

  static getDefaultDecks(): Decks {
    let decks = new Decks();
    const allCharacters = CSV.getSpells();

    for (let i = 0; i < 5; i++) {
      let characters: Character[] = [];

      for (let j = 0; j < 8; j++) {
        const character = allCharacters[j];
        characters.push(
          new Character(character.globalId, character.cardId, character.level),
        );
      }

      decks.decks.push(new Deck(characters));
    }

    return decks;
  }
}
