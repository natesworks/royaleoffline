import { Offsets } from "./offsets";
import {
  base,
  createMessageByType,
  messageManagerReceiveMessage,
  operator_new,
} from "./definitions";
import { PiranhaMessage } from "./piranhamessage";
import { Logger } from "./utility/logger";
import { OwnHomeDataMessage } from "./packets/server/home/ownhomedatamessage";
import { ByteStream } from "./bytestream";
import { NpcSectorStateMessage } from "./packets/server/battle/npcsectorstatemessage";
import { EndClientTurnMessage } from "./packets/client/home/endclientturnmessage";
import { LoginMessage } from "./packets/client/login/loginmessage";
import { ChangeAvatarNameMessage } from "./packets/client/home/changeavatarnamemessage";
import { AvatarNameCheckRequestMessage } from "./packets/client/home/avatarnamecheckrequestmessage";

export class Messaging {
  static sendOfflineMessage(id: number, payload: number[]): NativePointer {
    let version = id == 20104 ? 1 : 0;
    let message = createMessageByType(NULL, id);
    message.add(Offsets.Version).writeS32(version);
    const payloadLength = PiranhaMessage.getByteStream(message).add(
      Offsets.PayloadSize,
    );
    payloadLength.writeS32(payload.length);
    if (payload.length > 0) {
      let payloadPtr = operator_new(payload.length).writeByteArray(payload);
      PiranhaMessage.getByteStream(message)
        .add(Offsets.PayloadPtr)
        .writePointer(payloadPtr);
    }
    Logger.debug("Decoding", id);
    let decodeOffset = message.readPointer().add(Offsets.Decode).readPointer();
    //Logger.debug("Decode function for type", id + ":", decodeOffset.sub(base));
    let decode = new NativeFunction(decodeOffset, "void", ["pointer"]);
    decode(message);
    Logger.debug("Message", id, "decoded succesfully" + ", receiving");
    messageManagerReceiveMessage(
      base.add(Offsets.MessageManagerInstance).readPointer(),
      message,
    );
    Logger.debug("Message", id, "received");
    return message;
  }

  static handleMessage(id: number, messagePayload: number[]) {
    switch (id) {
      case 10101: {
        let message = new LoginMessage(messagePayload);
        message.decode();
        message.execute();
        break;
      }
      case 10212: {
        let message = new ChangeAvatarNameMessage(messagePayload);
        message.decode();
        message.execute();
        break;
      }
      case 14104: {
        //Messaging.sendOfflineMessage(21903, NpcSectorStateMessage.encode());
        break;
      }
      // gohomefromofflinepractice
      case 14101: {
        //Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode());
        break;
      }
      // endclientturn
      case 14102: {
        let message = new EndClientTurnMessage(messagePayload);
        message.decode();
        message.execute();
        break;
      }
      case 14600: {
        let message = new AvatarNameCheckRequestMessage(messagePayload);
        message.decode();
        message.execute();
        break;
      }
    }
  }
}
