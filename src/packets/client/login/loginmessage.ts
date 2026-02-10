import { Messaging } from "src/messaging";
import { userdata } from "src/definitions";
import { Logger } from "src/logger";
import { LogicScrollMessageFactory } from "src/logicscrollmessagefactory";
import { SCString } from "src/titan/utils/scstring";
import { GameMain } from "src/scroll/client/gamemain";

export class LoginMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  decode() {}

  execute() {
    let result = GameMain.loadAsset("sc/natesworks.sc");
    if (result) {
      Logger.debug("Loaded sc/natesworks.sc");
    } else {
      Logger.warn("sc/natesworks.sc is alreay loaded");
    }
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
