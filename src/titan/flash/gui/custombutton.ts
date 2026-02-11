import { base } from "src/base";
import { MovieClip } from "../movieclip";
import { Sprite } from "../sprite";
import { Logger } from "src/logger";
import { IButtonListener } from "./ibuttonlistener";

export class CustomButton extends Sprite {
  constructor(ptr: NativePointer) {
    super(ptr);
  }

  setMovieClip(movieclip: MovieClip | NativePointer) {
    const vtable = this.ptr.readPointer();
    return new NativeFunction(
      vtable.add(32 * Process.pointerSize).readPointer(),
      "int",
      ["pointer", "pointer", "bool"],
    )(
      this.ptr,
      movieclip instanceof NativePointer ? movieclip : movieclip.ptr,
      1,
    );
  }
}
