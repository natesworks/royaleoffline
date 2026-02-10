import { base } from "src/base";
import { Sprite } from "./sprite";
import { SCString } from "../utils/scstring";

const getMovieClipByName = new NativeFunction(base.add(0x23f989), "pointer", [
  "pointer",
  "pointer",
]);

export class MovieClip extends Sprite {
  constructor(ptr: NativePointer) {
    super(ptr);
  }

  getMovieClipByName(name: string) {
    return new MovieClip(
      getMovieClipByName(this.ptr, Memory.allocUtf8String(name)),
    );
  }
}
