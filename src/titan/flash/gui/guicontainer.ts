import { MovieClip } from "../movieclip";
import { Sprite } from "../sprite";

export class GUIContainer extends Sprite {
  constructor(ptr: NativePointer) {
    super(ptr);
  }

  getMovieClip(): MovieClip {
    return new MovieClip(this.ptr.add(80).readPointer());
  }
}
