import { LogicScrollMessageFactory } from "src/logicscrollmessagefactory";
import { Messaging } from "src/messaging";
import { Logger } from "src/utility/logger";

export class GoHomeFromOfflinePracticeMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  decode() {}

  execute() {
    let ohd = LogicScrollMessageFactory.createMessageByType(24101, []);
    ohd.encode();
    Messaging.sendOfflineMessage(ohd);
  }

  getMessageType() {
    return 10101;
  }
}
