import { malloc } from "./definitions";
import { Logger } from "./logger";
import { LogicScrollMessageFactory } from "./logicscrollmessagefactory";
import { base } from "./base";
import { PiranhaMessage } from "./titan/logic/message/piranhamessage";

const createMessageByType = new NativeFunction(base.add(0x1c011d), "pointer", [
  "pointer",
  "int",
]);
const receiveMessage = new NativeFunction(base.add(0x996dd), "int", [
  "pointer",
  "pointer",
]);

export class Messaging {
  static sendOfflineMessage(msg: any): NativePointer {
    const type = msg.getMessageType();
    const payload = msg.messagePayload;
    const name = msg.constructor.name;

    let version = type == 20104 ? 1 : 0;
    let message = createMessageByType(NULL, type);

    message.add(4).writeS32(version);
    const payloadLength = PiranhaMessage.getByteStream(message).add(20);
    payloadLength.writeS32(payload.length);

    if (payload.length > 0) {
      let payloadPtr = malloc(payload.length).writeByteArray(payload);
      PiranhaMessage.getByteStream(message).add(28).writePointer(payloadPtr);
    }

    let decodeOffset = message
      .readPointer()
      .add(3 * Process.pointerSize)
      .readPointer();
    //Logger.debug("Decode function for type", id + ":", decodeOffset.sub(base));
    let decode = new NativeFunction(decodeOffset, "void", ["pointer"]);
    decode(message);

    Logger.debug("Decoded", name);

    receiveMessage(base.add(0x59ca60).readPointer(), message);

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
