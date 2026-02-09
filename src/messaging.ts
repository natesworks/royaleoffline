import { Offsets } from "./offsets";
import {
  base,
  createMessageByType,
  messageManagerReceiveMessage,
  operator_new,
} from "./definitions";
import { PiranhaMessage } from "./piranhamessage";
import { Logger } from "./utility/logger";
import { LogicScrollMessageFactory } from "./logicscrollmessagefactory";

export class Messaging {
  static sendOfflineMessage(msg: any): NativePointer {
    const type = msg.getMessageType();
    const payload = msg.messagePayload;
    const name = msg.constructor.name;

    let version = type == 20104 ? 1 : 0;
    let message = createMessageByType(NULL, type);

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

    let decodeOffset = message.readPointer().add(Offsets.Decode).readPointer();
    //Logger.debug("Decode function for type", id + ":", decodeOffset.sub(base));
    let decode = new NativeFunction(decodeOffset, "void", ["pointer"]);
    decode(message);

    Logger.debug("Decoded", name);

    messageManagerReceiveMessage(
      base.add(Offsets.MessageManagerInstance).readPointer(),
      message,
    );

    Logger.debug(name, "received");
    return message;
  }

  static handleMessage(type: number, messagePayload: number[]) {
    let message = LogicScrollMessageFactory.createMessageByType(
      type,
      messagePayload,
    );
    message.decode();
    message.execute();
  }
}
