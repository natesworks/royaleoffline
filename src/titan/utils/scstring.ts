import { Logger } from "src/logger";
import { base } from "src/base";
import { malloc } from "src/definitions";

const getString = new NativeFunction(base.add(0xbf845), "pointer", ["pointer"]);
const nativeConstructor = new NativeFunction(base.add(0x1feb71), "pointer", [
  "pointer",
  "pointer",
]);

export class SCString {
  ptr: NativePointer;

  constructor(contents: string) {
    this.ptr = malloc(128);
    nativeConstructor(this.ptr, Memory.allocUtf8String(contents));
  }

  static fromPtr(ptr: NativePointer): SCString {
    const obj = Object.create(SCString.prototype) as SCString;
    obj.ptr = ptr;
    return obj;
  }

  readContents(): string {
    let len = this.ptr.add(4).readInt();
    let result: string | null;

    if (len >= 8) {
      result = this.ptr.add(8).readPointer().readUtf8String(len);
    } else {
      result = this.ptr.add(8).readUtf8String(len);
    }

    if (!result) {
      Logger.error("Failed to read contents of string");
      return "";
    }

    return result;
  }

  static get(tid: string): SCString {
    return SCString.fromPtr(getString(new SCString(tid).ptr));
  }
}
