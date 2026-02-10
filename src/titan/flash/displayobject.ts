import { base } from "src/base";
import { Logger } from "src/logger";

const setHeight = new NativeFunction(base.add(0x23db01), "void", [
  "pointer",
  "float",
]);
const setWidth = new NativeFunction(base.add(0x23db61), "void", [
  "pointer",
  "float",
]);

export class DisplayObject {
  ptr: NativePointer;

  constructor(ptr: NativePointer) {
    this.ptr = ptr;
  }

  getHeight(): number {
    const vtable = this.ptr.readPointer();
    return new NativeFunction(
      vtable.add(12 * Process.pointerSize).readPointer(),
      "float",
      ["pointer"],
    )(this.ptr);
  }

  getWidth(): number {
    const vtable = this.ptr.readPointer();
    return new NativeFunction(
      vtable.add(11 * Process.pointerSize).readPointer(),
      "float",
      ["pointer"],
    )(this.ptr);
  }

  setHeight(value: number) {
    return setHeight(this.ptr, value);
  }

  setWidth(value: number) {
    return setWidth(this.ptr, value);
  }

  get x(): number {
    return this.ptr.add(12).add(16).readFloat();
  }

  get y(): number {
    return this.ptr.add(12).add(20).readFloat();
  }

  set x(value: number) {
    this.ptr.add(12).add(16).writeFloat(value);
  }

  set y(value: number) {
    this.ptr.add(12).add(20).writeFloat(value);
  }
}
