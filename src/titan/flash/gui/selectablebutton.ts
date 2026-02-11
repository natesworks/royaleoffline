import { CustomButton } from "./custombutton";

export class SelectableButton extends CustomButton {
  constructor(ptr: NativePointer) {
    super(ptr);
  }

  isSelected(): boolean {
    const vtable = this.ptr.readPointer();
    return Boolean(
      new NativeFunction(
        vtable.add(42 * Process.pointerSize).readPointer(),
        "bool",
        ["pointer"],
      )(this.ptr),
    );
  }

  setSelected(value: boolean) {
    const vtable = this.ptr.readPointer();
    return new NativeFunction(
      vtable.add(41 * Process.pointerSize).readPointer(),
      "void",
      ["pointer", "bool"],
    )(this.ptr, Number(value));
  }
}
