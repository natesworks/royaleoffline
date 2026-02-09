import {
  gameButtonContructor,
  getMovieClip,
  malloc,
  setDisplayObject,
  setXY,
  spriteAddChild,
} from "src/definitions";
import { Logger } from "./logger";

export class ButtonHelper {
  static createButton(
    guiContainer: NativePointer,
    scFile: string,
    item: string,
    init = true,
    x: number,
    y: number,
  ) {
    let button = malloc(256);
    gameButtonContructor(button);
    let movieclip = getMovieClip(
      Memory.allocUtf8String(scFile),
      Memory.allocUtf8String(item),
    );
    setDisplayObject(button, movieclip, Number(init));
    setXY(button, x, y);
    spriteAddChild(guiContainer, button);
    Logger.debug("Added button");
  }
}
