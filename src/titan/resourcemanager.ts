import { base } from "src/base";
import { MovieClip } from "./flash/movieclip";

const getMovieClip = new NativeFunction(base.add(0x2269a1), "pointer", [
  "pointer",
  "pointer",
]);

export class ResourceManager {
  static getMovieClip(scFile: string, exportName: string): MovieClip {
    return new MovieClip(
      getMovieClip(
        Memory.allocUtf8String(scFile),
        Memory.allocUtf8String(exportName),
      ),
    );
  }
}
