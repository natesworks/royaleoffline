import { ByteStream } from "src/bytestream";
import { Messaging } from "src/messaging";
import { OwnHomeDataMessage } from "src/packets/server/home/ownhomedatamessage";
import { LoginOkMessage } from "src/packets/server/login/loginokmessage";
import { loadAsset, userdata } from "src/definitions";
import { createStringObject } from "src/util";
import { Logger } from "src/utility/logger";

export class LoginMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  decode() {}

  execute() {
    let result = loadAsset(createStringObject("sc/natesworks.sc"));
    if (result) {
      Logger.debug("Loaded sc/natesworks.sc");
    } else {
      Logger.warn("sc/natesworks.sc is alreay loaded");
    }
    userdata.read();
    Messaging.sendOfflineMessage(20104, LoginOkMessage.encode());
    Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode());
  }

  getMessageType() {
    return 10101;
  }
}
