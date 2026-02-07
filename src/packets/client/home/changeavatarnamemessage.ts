import { ByteStream } from "src/bytestream";
import { Messaging } from "src/messaging";
import { userdata } from "src/definitions";
import { Logger } from "src/utility/logger";
import { LogicChangeNameCommand } from "src/commands/server/home/logicchangenamecommand";

export class ChangeAvatarNameMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  name = "";

  decode() {
    let stream = new ByteStream(this.messagePayload);

    this.name = stream.readString();
  }

  execute() {
    let command = new LogicChangeNameCommand();

    command.name = this.name;
    command.nameset = true;

    let stream = new ByteStream([]);
    command.encode(stream);
    Messaging.sendOfflineMessage(24111, stream.payload);

    userdata.name = this.name;
    userdata.registered = true;
    userdata.write();

    Logger.debug("Set name to", userdata.name);
  }

  getMessageType() {
    return 10212;
  }
}
