import { ByteStream } from "src/bytestream";

export class AvatarNameCheckResponseMessage {
  messagePayload: number[];

  // error codes:
  // 1 = invalid
  // 2 = too short
  // 3 = already changed
  // 4 = invalid mirror
  // 5 = low level
  errorCode = 0;
  name = "";

  constructor(messagePayload: number[]) {
    this.messagePayload = messagePayload;
  }

  encode() {
    let stream = new ByteStream([]);

    stream.writeBoolean(this.errorCode != 0); // is invalid
    stream.writeInt(this.errorCode);
    stream.writeString(this.name);

    this.messagePayload = stream.payload;
  }

  getMessageType() {
    return 20300;
  }
}
