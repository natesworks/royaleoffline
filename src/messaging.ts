import { Offsets } from "./offsets";
import {
  base,
  createMessageByType,
  messageManagerReceiveMessage,
  operator_new,
} from "./definitions";
import { PiranhaMessage } from "./piranhamessage";
import { getMessageManagerInstance } from "./util";
import { OwnHomeDataMessage } from "OwnHomeDataMessage";
import { Logger } from "./utility/logger";
import { LoginOkMessage } from "./packets/server/loginokmessage";
import { ByteStream } from "./bytestream";
import { NpcSectorStateMessage } from "./packets/server/battle/npcsectorstatemessage";
import { EndClientTurnMessage } from "./packets/client/endclientturnmessage";

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
      // LoginMessage
      case 10101: {
        Messaging.sendOfflineMessage(20104, LoginOkMessage.encode());
        Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode());
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
      // keepalive
      case 10108: {
        Messaging.sendOfflineMessage(20108, []);
        break;
      }
    }
  }
}
