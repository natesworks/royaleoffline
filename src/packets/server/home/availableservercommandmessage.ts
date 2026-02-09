import { ByteStream } from "src/bytestream";

export class AvailableServerCommandMessage {
  messagePayload: number[];

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  encode() {}

  getMessageType() {
    return 24111;
  }
}
