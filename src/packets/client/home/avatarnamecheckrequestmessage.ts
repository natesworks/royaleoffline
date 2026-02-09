import { ByteStream } from "src/bytestream";
import { Messaging } from "src/messaging";
import { AvatarNameCheckResponseMessage } from "src/packets/server/home/avatarnamecheckresponsemessage";

export class AvatarNameCheckRequestMessage {
  messagePayload: number[];

  name = "";

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  decode() {
    let stream = new ByteStream(this.messagePayload);

    this.name = stream.readString();
  }

  execute() {
    let message = new AvatarNameCheckResponseMessage([]);
    message.name = this.name;
    message.encode();

    Messaging.sendOfflineMessage(message);
  }

  getMessageType() {
    return 14600;
  }
}
