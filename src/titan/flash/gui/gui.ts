import { base } from "src/base";
import { Logger } from "src/logger";

const getInstance = new NativeFunction(base.add(0x8d775), "pointer", []);
const showPopup = new NativeFunction(base.add(0x8df25), "void", [
  "pointer",
  "pointer",
  "bool",
  "bool",
  "bool",
]);

export class GUI {
  ptr: NativePointer;

  constructor(ptr: NativePointer) {
    this.ptr = ptr;
  }

  static showPopup(ptr: NativePointer, a2: number, a3: number, a4: number) {
    return showPopup(this.ptr, ptr, a2, a3, a4);
  }

  static get ptr(): NativePointer {
    return getInstance();
  }
}
