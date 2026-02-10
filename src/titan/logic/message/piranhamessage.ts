export class PiranhaMessage {
  static getMessageType(message: NativePointer): number {
    let vtable = message.readPointer();
    let getMessageType = new NativeFunction(
      vtable.add(5 * Process.pointerSize).readPointer(),
      "int",
      [],
    );
    return getMessageType();
  }

  static destroyMessage(message: NativePointer): void {
    let vtable = message.readPointer();
    let destroyMessage = new NativeFunction(
      vtable.add(6 * Process.pointerSize).readPointer(),
      "void",
      ["pointer"],
    );
    return destroyMessage(message); // no need to ret but looks better imo
  }

  static getEncodingLength(message: NativePointer): number {
    let stream = this.getByteStream(message);
    let size = stream.add(20).readS32();
    let offset = stream.add(16).readS32();
    return offset > size ? offset : size;
  }

  static getByteStream(message: NativePointer): NativePointer {
    return message.add(8);
  }

  static encode(message: NativePointer): NativePointer {
    let vtable = message.readPointer();
    const encode = new NativeFunction(
      vtable.add(2 * Process.pointerSize).readPointer(),
      "pointer",
      ["pointer"],
    );
    return encode(message);
  }
}
