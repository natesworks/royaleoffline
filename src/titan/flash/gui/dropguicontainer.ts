import { base } from "src/base";
import { GameButton } from "./gamebutton";
import { GUIContainer } from "./guicontainer";

const addGameButton = new NativeFunction(base.add(0x96c6d), "pointer", [
  "pointer",
  "pointer",
  "bool",
]);

export class DropGUIContainer extends GUIContainer {
  constructor(ptr: NativePointer) {
    super(ptr);
  }

  addGameButton(button: string) {
    return new GameButton(
      addGameButton(this.ptr, Memory.allocUtf8String(button), 1),
    );
  }
}
