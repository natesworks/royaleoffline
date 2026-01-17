import { ByteStream } from "src/bytestream.js";

export class OwnHomeDataMessage {
  static encode(): number[] {
    let stream = new ByteStream([]);

    // todo

    return stream.payload;
  }
}
