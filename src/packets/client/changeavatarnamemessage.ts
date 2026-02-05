import { ByteStream } from "src/bytestream";
import { Messaging } from "src/messaging";
import { userdata } from "src/definitions";
import { Logger } from "src/utility/logger";
import {
  LogicChangeNameCommand,
  LogicChangeNameCommandData,
} from "src/commands/server/logicchangenamecommand";

export class ChangeAvatarNameMessageData {
  name: string;

  constructor(name: string) {
    this.name = name;
  }
}

export class ChangeAvatarNameMessage {
  static decode(stream: ByteStream): ChangeAvatarNameMessageData {
    let name = stream.readString();

    return new ChangeAvatarNameMessageData(name);
  }

  static execute(data: ChangeAvatarNameMessageData) {
    let changeNameData = new LogicChangeNameCommandData(data.name, true);

    Messaging.sendOfflineMessage(
      24111,
      LogicChangeNameCommand.encode(changeNameData),
    );

    userdata.registered = true;
    userdata.name = data.name;
    userdata.write();

    Logger.debug("Set name to", userdata.name);
  }
}
