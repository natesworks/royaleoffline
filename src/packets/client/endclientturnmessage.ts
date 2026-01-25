import { ByteStream } from "../../bytestream.js";
import { CommandHandler } from "../../commandhandler.js";
import { Logger } from "../../utility/logger.js";

export class EndClientTurnMessage {
  static decode(stream: ByteStream) {
    stream.readBoolean();
    let tick = stream.readVInt();
    let checksum = stream.readVInt();
    let count = stream.readVInt();
    Logger.verbose("Command amount:", count);
    return { stream, tick, checksum, count };
  }

  static execute(data: {
    stream: ByteStream;
    tick: number;
    checksum: number;
    count: number;
  }) {
    let { stream, count } = data;
    for (let i = 0; i < count; i++) {
      let id = stream.readVInt();
      Logger.verbose("Command ID:", id);
      stream = CommandHandler.handleCommand(id, stream);
    }
  }
}
