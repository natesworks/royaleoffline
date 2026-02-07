import { ByteStream } from "src/bytestream";

export class BattleResultMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  encode() {
    let stream = new ByteStream([]);

    stream.writeVInt(1);
    stream.writeVInt(1); // Trophies (Own)

    stream.writeVInt(0);
    stream.writeVInt(1); // Trophies (Opponent)

    stream.writeVInt(0);
    stream.writeVInt(63);

    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(3);
    stream.writeVInt(0);
    stream.writeVInt(19);
    stream.writeVInt(225);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(4);
    stream.writeVInt(47);
    stream.writeVInt(1260);
    stream.writeVInt(1293);
    stream.writeVInt(11);
    stream.writeVInt(1260);

    // Treasure Chest
    stream.writeVInt(58);
    stream.writeVInt(205);

    stream.writeVInt(21);
    stream.writeVInt(1);

    this.messagePayload = stream.payload;
  }

  getMessageType() {
    return 20225;
  }
}
