import { ByteStream } from "src/bytestream";
import { Messaging } from "src/messaging";
import { NpcSectorStateMessage } from "src/packets/server/battle/npcsectorstatemessage";

export class StartMissionMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  decode() {
    let stream = new ByteStream(this.messagePayload);

    stream.readDataReference();
  }

  execute() {
    let npcSectorStateMessage = new NpcSectorStateMessage([]);
    npcSectorStateMessage.encode();

    Messaging.sendOfflineMessage(npcSectorStateMessage);
  }

  getMessageType() {
    return 14104;
  }
}
