import { Messaging } from "src/messaging";
import { OwnHomeDataMessage } from "src/packets/server/home/ownhomedatamessage";
import { initBattleSettings, loadAsset, userdata } from "src/definitions";
import { createStringObject } from "src/util";
import { Logger } from "src/utility/logger";
import { LogicScrollMessageFactory } from "src/logicscrollmessagefactory";

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
    initBattleSettings();
    userdata.read();

    let loginOk = LogicScrollMessageFactory.createMessageByType(20104, []);
    loginOk.encode();
    Messaging.sendOfflineMessage(loginOk);

    let ohd = LogicScrollMessageFactory.createMessageByType(24101, []);
    ohd.encode();
    Messaging.sendOfflineMessage(ohd);
  }

  getMessageType() {
    return 10101;
  }
}
