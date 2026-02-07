import { ByteStream } from "src/bytestream.js";
import { CommandHandler } from "src/commandhandler.js";
import { Logger } from "src/utility/logger.js";

export class EndClientTurnMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  tick = 0;
  checksum = 0;
  count = 0;

  commands: any[] = [];

  decode() {
    let stream = new ByteStream(this.messagePayload);

    this.tick = stream.readVInt();
    this.checksum = stream.readVInt();
    this.count = stream.readVInt();
    Logger.verbose("Command amount:", this.count);

    for (let i = 0; i < this.count; i++) {
      let id = stream.readVInt();
      Logger.verbose("Command Id:", id);
      let command = CommandHandler.createCommandOfType(id);
      command.decode(stream);
      this.commands.push(command);
    }
  }

  execute() {
    for (let i = 0; i < this.count; i++) {
      this.commands[i].execute();
    }
  }

  getMessageType() {
    return 14102;
  }
}
