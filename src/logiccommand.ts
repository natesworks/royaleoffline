import { ByteStream } from "./bytestream.js";

export class LogicCommand {
  static encode(stream: ByteStream) {
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVLong(0, 1);
  }

  static decode(stream: ByteStream) {
    stream.readVInt(); // tick
    stream.readVInt(); // checksum
    stream.readVLong(); // executor id
  }
}
