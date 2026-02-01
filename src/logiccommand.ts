import { ByteStream } from "./bytestream.js";
import { CommandData } from "./commanddata.js";

export class LogicCommand {
  static encode(stream: ByteStream, data: CommandData) {
    stream.writeVInt(data.tick);
    stream.writeVInt(0);
    const high = Number(BigInt(data.executorId) >> 32n);
    const low = Number(BigInt(data.executorId) & 0xffffffffn);
    stream.writeVLong(high, low);
  }

  static decode(stream: ByteStream): CommandData {
    let data = new CommandData();
    data.tick = stream.readVInt();
    stream.readVInt(); // checksum
    data.executorId = stream.readVLong();
    return data;
  }
}
