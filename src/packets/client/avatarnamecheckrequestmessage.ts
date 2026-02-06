import { ByteStream } from "src/bytestream";
import { Messaging } from "src/messaging";
import {
  AvatarNameCheckResponseMessage,
  AvatarNameCheckResponseMessageData,
} from "../server/avatarnamecheckresponsemessage";

export class AvatarNameCheckRequestMessageData {
  name = "";
}

export class AvatarNameCheckRequestMessage {
  static id = 14600;

  static decode(stream: ByteStream): AvatarNameCheckRequestMessageData {
    let data = new AvatarNameCheckRequestMessageData();

    data.name = stream.readString();

    return data;
  }

  static execute(data: AvatarNameCheckRequestMessageData) {
    let responseData = new AvatarNameCheckResponseMessageData(data.name);

    Messaging.sendOfflineMessage(
      AvatarNameCheckResponseMessage.id,
      AvatarNameCheckResponseMessage.encode(responseData),
    );
  }
}
