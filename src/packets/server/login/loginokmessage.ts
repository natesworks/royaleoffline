import { ByteStream } from "src/bytestream";

export class LoginOkMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  static encode(): number[] {
    let stream = new ByteStream([]);

    stream.writeLong(0, 1);
    stream.writeLong(0, 1);
    stream.writeString(""); // token
    stream.writeString("");
    stream.writeString("");
    stream.writeVInt(1); // doesnt matter
    stream.writeVInt(2);
    stream.writeVInt(3);
    stream.writeString("dev");
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeString("");
    stream.writeString("");
    stream.writeString("");
    stream.writeVInt(0);
    stream.writeString("G:1");
    stream.writeString("");
    stream.writeString("DE");
    stream.writeString("Berlin");

    stream.writeString("");
    stream.writeString("");
    stream.writeString("");

    return stream.payload;
  }

  getMessageType() {
    return 20104;
  }
}
