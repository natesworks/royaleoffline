import { ByteStream } from "src/bytestream";

export class AvatarNameCheckResponseMessageData {
  errorCode: number;
  name: string;

  constructor(name: string, errorCode: number = 0) {
    this.name = name;
    this.errorCode = errorCode;
  }
}

export class AvatarNameCheckResponseMessage {
  static id = 20300;

  static encode(data: AvatarNameCheckResponseMessageData): number[] {
    let stream = new ByteStream([]);

    // error codes:
    // 1 = invalid
    // 2 = too short
    // 3 = already changed
    // 4 = invalid mirror
    // 5 = low level

    stream.writeBoolean(data.errorCode != 0); // is invalid
    stream.writeInt(data.errorCode);
    stream.writeString(data.name);

    return stream.payload;
  }
}
