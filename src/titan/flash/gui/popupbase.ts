import { base } from "src/base";
import { SCString } from "src/titan/utils/scstring";
import { DropGUIContainer } from "./dropguicontainer";
import { malloc } from "src/definitions";

const nativeConstructor = new NativeFunction(base.add(0x11ad59), "pointer", [
  "pointer",
  "pointer",
  "pointer",
  "bool",
  "bool",
]);

export class PopupBase extends DropGUIContainer {
  constructor(scFile: string, exportName: string) {
    const ptr = malloc(256);
    super(ptr);

    nativeConstructor(
      ptr,
      new SCString(scFile).ptr,
      new SCString(exportName).ptr,
      1,
      0,
    );
    ptr.writePointer(base.add(0x502ca0));
    ptr.add(0x48).writePointer(base.add(0x502d7c));

    for (let i = 0; i < 30; i++) {
      ptr.add(0x98).add(i).writeU8(0);
    }
  }

  modalClose() {
    let vtable = this.ptr.readPointer();
    let modalClose = new NativeFunction(
      vtable.add(0xa4).readPointer(),
      "void",
      ["pointer"],
    );
    modalClose(this.ptr);
  }
}
