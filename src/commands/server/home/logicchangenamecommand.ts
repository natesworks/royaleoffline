import { ByteStream } from "src/bytestream";
import { LogicCommand } from "src/logiccommand";

export class LogicChangeNameCommand {
  static commandId = 201;

  name = "";
  nameset = false;

  encode(stream: ByteStream) {
    stream.writeVInt(LogicChangeNameCommand.commandId);

    stream.writeString(this.name);
    stream.writeInt(Number(this.nameset));

    LogicCommand.encode(stream);
  }
}
