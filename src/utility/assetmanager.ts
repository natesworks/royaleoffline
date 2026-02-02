// gud <3

import { base } from "src/definitions";
import { Offsets } from "src/offsets";
import { Logger } from "./logger";

export class AssetManager {
  static readFromAssets(assetName: string): string {
    const libandroid = Process.getModuleByName("libandroid.so");

    const AAssetManager_open = new NativeFunction(
      libandroid.getExportByName("AAssetManager_open"),
      "pointer",
      ["pointer", "pointer", "int"],
    );

    const AAsset_getLength = new NativeFunction(
      libandroid.getExportByName("AAsset_getLength"),
      "int",
      ["pointer"],
    );

    const AAsset_read = new NativeFunction(
      libandroid.getExportByName("AAsset_read"),
      "int",
      ["pointer", "pointer", "int"],
    );

    const AAsset_close = new NativeFunction(
      libandroid.getExportByName("AAsset_close"),
      "void",
      ["pointer"],
    );

    const filename = Memory.allocUtf8String(assetName);
    const asset = AAssetManager_open(
      base.add(Offsets.AAssetManager).readPointer(),
      filename,
      2,
    );

    if (asset.isNull()) {
      Logger.error("Asset is NULL");
      throw new Error();
    }

    const length = AAsset_getLength(asset);
    const buffer = Memory.alloc(length);
    AAsset_read(asset, buffer, length);
    AAsset_close(asset);
    let contents = buffer.readUtf8String(length);
    if (contents) return contents;
    Logger.error("Failed to read contents");
    throw Error();
  }
}
