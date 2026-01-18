import { ByteStream } from "../../bytestream";

export class LoginOkMessage {
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

    stream.writeString("https://game-assets.clashroyaleapp.com");
    stream.writeString("https://game-assets.clashroyaleapp.com/");
    stream.writeString("https://event-assets.clashroyale.com");

    return stream.payload;
  }
}
