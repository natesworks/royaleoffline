import { ByteStream } from "./bytestream";
import { DeckHelper, Decks } from "./deck";
import { access, documentsDirectory, unlink } from "./definitions";
import { Logger } from "./logger";

export class UserData {
  name = "";
  registered = false;
  decks = new Decks();

  infiniteElixirEnabled = false;

  write() {
    const path = documentsDirectory + "/userdata.bin";
    unlink(Memory.allocUtf8String(path));

    let stream = new ByteStream([]);

    let version = 1;
    stream.writeByte(version);

    stream.writeString(this.name);
    stream.writeBoolean(this.infiniteElixirEnabled);
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
    if (version > 1) {
      let text = "Unsupported user data version";
      Logger.warn(text);
      this.write();
    }

    let name = stream.readString();
    this.name = name;
    this.registered = name != "";
    this.infiniteElixirEnabled = stream.readBoolean();

    let decks = DeckHelper.readDecks(stream);
    this.decks = decks;
  }
}
