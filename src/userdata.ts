import { ByteStream } from "./bytestream";
import { DeckHelper, Decks } from "./deck";
import {
  access,
  base,
  documentsDirectory,
  showCenteredFloaterText,
  unlink,
} from "./definitions";
import { Offsets } from "./offsets";
import { createStringObject } from "./util";
import { Logger } from "./utility/logger";

export class UserData {
  name = "";
  registered = false;
  decks = new Decks();

  write() {
    const path = documentsDirectory + "/userdata.bin";
    unlink(Memory.allocUtf8String(path));

    let stream = new ByteStream([]);

    let version = 1;
    stream.writeByte(version);

    stream.writeString(this.name);
    DeckHelper.writeDecks(stream, this.decks);

    File.writeAllBytes(path, stream.payload);
  }

  read() {
    const path = documentsDirectory + "/userdata.bin";

    if (access(Memory.allocUtf8String(path), 0) === -1) {
      this.decks = DeckHelper.getDefaultDecks();
      this.write();
    }

    const data = File.readAllBytes(path);
    const stream = new ByteStream(Array.from(new Uint8Array(data)));

    let version = stream.readByte();
    if (version != 1) {
      let text = "Unsupported user data version";
      Logger.warn(text);
      this.write();
    }

    let name = stream.readString();
    this.name = name;
    this.registered = name != "";

    let decks = DeckHelper.readDecks(stream);
    this.decks = decks;
  }
}
