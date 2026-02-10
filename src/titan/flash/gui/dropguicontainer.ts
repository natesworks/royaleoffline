import { base } from "src/base";
import { GameButton } from "./gamebutton";

const addGameButton = new NativeFunction(base.add(0x96c6d), "pointer", [
  "pointer",
  "pointer",
  "bool",
]);

export class DropGUIContainer {
  ptr: NativePointer;

  constructor(ptr: NativePointer) {
    this.ptr = ptr;
  }

  addGameButton(button: string) {
    return new GameButton(
      addGameButton(this.ptr, Memory.allocUtf8String(button), 1),
    );
  }
}
