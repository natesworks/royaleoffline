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
    let avatarNameCheckResponseMessage = new AvatarNameCheckResponseMessage([]);
    avatarNameCheckResponseMessage.name = this.name;
    avatarNameCheckResponseMessage.encode();

    Messaging.sendOfflineMessage(
      avatarNameCheckResponseMessage.getMessageType(),
      avatarNameCheckResponseMessage.messagePayload,
    );
  }

  getMessageType() {
    return 14600;
  }
}
