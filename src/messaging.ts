import { Offsets } from "./offsets";
import {
  base,
  createMessageByType,
  messageManagerReceiveMessage,
  operator_new,
} from "./definitions";
import { PiranhaMessage } from "./piranhamessage";
import { Logger } from "./utility/logger";
import { OwnHomeDataMessage } from "./packets/server/ownhomedatamessage";
import { ByteStream } from "./bytestream";
import { NpcSectorStateMessage } from "./packets/server/battle/npcsectorstatemessage";
import { EndClientTurnMessage } from "./packets/client/endclientturnmessage";
import { LoginMessage } from "./packets/client/loginmessage";
import { ChangeAvatarNameMessage } from "./packets/client/changeavatarnamemessage";
import { AvatarNameCheckRequestMessage } from "./packets/client/avatarnamecheckrequestmessage";

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

  static handleMessage(id: number, stream: ByteStream) {
    switch (id) {
      case 10101: {
        let data = LoginMessage.decode(stream);
        LoginMessage.execute(data);
        break;
      }
      case 10212: {
        let data = ChangeAvatarNameMessage.decode(stream);
        ChangeAvatarNameMessage.execute(data);
        break;
      }
      case 14104: {
        Messaging.sendOfflineMessage(21903, NpcSectorStateMessage.encode());
        break;
      }
      // gohomefromofflinepractice
      case 14101: {
        Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode());
        break;
      }
      // endclientturn
      case 14102: {
        let data = EndClientTurnMessage.decode(stream);
        EndClientTurnMessage.execute(data);
        break;
      }
      case AvatarNameCheckRequestMessage.id: {
        let data = AvatarNameCheckRequestMessage.decode(stream);
        AvatarNameCheckRequestMessage.execute(data);
        break;
      }
    }
  }
}
