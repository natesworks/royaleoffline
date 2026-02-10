import { base } from "src/base";
import { DisplayObject } from "./displayobject";

const addChild = new NativeFunction(base.add(0x24308d), "void", [
  "pointer",
  "pointer",
]);

export class Sprite extends DisplayObject {
  constructor(ptr: NativePointer) {
    super(ptr);
  }

  addChild(child: NativePointer | DisplayObject) {
    addChild(this.ptr, child instanceof NativePointer ? child : child.ptr);
  }
}
