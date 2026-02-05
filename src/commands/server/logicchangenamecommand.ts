import { ByteStream } from "src/bytestream";
import { LogicCommand } from "src/logiccommand";

export class LogicChangeNameCommandData {
  name: string;
  nameset: boolean;

  constructor(name: string, nameset: boolean) {
    this.name = name;
    this.nameset = nameset;
  }
}

export class LogicChangeNameCommand {
  static commandId = 201;

  static encode(data: LogicChangeNameCommandData): number[] {
    let stream = new ByteStream([]);

    stream.writeVInt(this.commandId);

    stream.writeString(data.name);
    stream.writeInt(Number(data.nameset));

    LogicCommand.encode(stream);

    return stream.payload;
  }
}
