import { GlobalId } from "src/globalid.js";
import { ByteStream } from "../../bytestream.js";
import { LogicCommand } from "../../logiccommand.js";
import { Logger } from "../../utility/logger.js";
import { Messaging } from "src/messaging.js";
import { CommandData } from "src/commanddata.js";

export class DoSpellData extends CommandData {
  spellDeckIndex = 0;
  spellId = 0;
  spellIndex = 0;
  troopLevel = 0;
  posX = 0;
  posY = 0;
}

export class LogicDoSpellCommand {
  static commandId = 1;

  static decode(stream: ByteStream): DoSpellData {
    let data = new DoSpellData();
    let commandData = new CommandData();
    commandData = LogicCommand.decode(stream);
    data.tick = commandData.tick;
    data.executorId = commandData.executorId;

    data.spellDeckIndex = stream.readVInt();
    data.spellId = stream.readDataReference();
    data.spellIndex = stream.readVInt();
    data.troopLevel = stream.readVInt();
    data.posX = stream.readVInt();
    data.posY = stream.readVInt();

    return data;
  }

  static encode(data: DoSpellData): ByteStream {
    let stream = new ByteStream([]);

    stream.writeVInt(0); // turn
    stream.writeVInt(0);
    stream.writeVInt(1); // command count
    stream.writeVInt(this.commandId);

    LogicCommand.encode(stream, data);

    stream.writeVInt(data.spellDeckIndex);
    stream.writeDataReference(data.spellId);
    stream.writeVInt(data.spellIndex);
    stream.writeVInt(data.troopLevel);
    stream.writeVInt(data.posX + 100);
    stream.writeVInt(data.posY - 100);

    return stream;
  }

  static execute(data: DoSpellData) {
    let stream = this.encode(data);
    Messaging.sendOfflineMessage(21902, stream.payload);
  }
}
