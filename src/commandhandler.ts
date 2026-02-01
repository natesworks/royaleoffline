import { ByteStream } from "./bytestream";
import { Logger } from "./utility/logger";

export class CommandHandler {
  static handleCommand(id: number, stream: ByteStream): ByteStream | null {
    switch (id) {
      default:
        Logger.warn("Unhandled command of type:", id);
        return null;
    }
    return stream;
  }
}
