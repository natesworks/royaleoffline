import { base } from "src/base";
import { CustomButton } from "./custombutton";
import { SCString } from "src/titan/utils/scstring";
import { Logger } from "src/logger";
import { malloc } from "src/definitions";

const nativeConstructor = new NativeFunction(base.add(0x90305), "pointer", [
  "pointer",
]);

export class GameButton extends CustomButton {
  constructor(ptr?: NativePointer) {
    if (!ptr) {
      ptr = malloc(200);
      nativeConstructor(ptr);
    }

    super(ptr);
  }

  setText(textField: string, text: string) {
    const vtable = this.ptr.readPointer();
    return new NativeFunction(
      vtable.add(42 * Process.pointerSize).readPointer(),
      "int",
      ["pointer", "pointer", "pointer"],
    )(this.ptr, Memory.allocUtf8String(textField), new SCString(text).ptr);
  }
}
