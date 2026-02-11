import { base } from "src/base";

const getGameModeInstance = new NativeFunction(
  base.add(0xb9ad9),
  "pointer",
  [],
);
const setPaused = new NativeFunction(base.add(0xbb309), "void", [
  "pointer",
  "bool",
]);

export class GameMode {
  ptr: NativePointer;

  constructor(ptr: NativePointer) {
    this.ptr = ptr;
  }

  setPaused(value: boolean) {
    setPaused(this.ptr, Number(value));
  }

  static getInstance(): NativePointer {
    return getGameModeInstance();
  }
}
