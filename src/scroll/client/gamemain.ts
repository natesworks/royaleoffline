import { base } from "src/base";
import { SCString } from "src/titan/utils/scstring";

const loadAsset = new NativeFunction(base.add(0x6b60d), "bool", ["pointer"]);

export class GameMain {
  static loadAsset(path: string): number {
    return loadAsset(new SCString(path).ptr);
  }
}
