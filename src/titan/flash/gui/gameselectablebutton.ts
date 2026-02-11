import { malloc } from "src/definitions";
import { SelectableButton } from "./selectablebutton";
import { base } from "src/base";
import { SCString } from "src/titan/utils/scstring";

const nativeConstructor = new NativeFunction(base.add(0x91789), "pointer", [
  "pointer",
  "pointer",
]);
const setText = new NativeFunction(base.add(0x91985), "void", [
  "pointer",
  "pointer",
  "pointer",
  "bool",
]);

export class GameSelectableButton extends SelectableButton {
  constructor(ptr?: NativePointer) {
    if (!ptr) {
      ptr = malloc(200);
      nativeConstructor(ptr, NULL);
    }
    super(ptr);
  }

  setText(textField: string, text: string) {
    return setText(
      this.ptr,
      Memory.allocUtf8String(textField),
      new SCString(text).ptr,
      0,
    );
  }
}
