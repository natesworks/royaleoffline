import {
  addGameButton,
  base,
  gameButtonContructor,
  getGUIInstance,
  getHeight,
  getMovieClip,
  getMovieClipByName,
  getString,
  getTextFieldByName,
  getWidth,
  malloc,
  popupBaseConstructor,
  setDisplayObject,
  setHeight,
  setPixelSnappedXY,
  setWidth,
  setXY,
  showPopup,
  spriteAddChild,
} from "./definitions";
import { Offsets } from "./offsets";
import { createStringObject } from "./util";
import { Logger } from "./utility/logger";

export class BattleSettings {
  settingsButton: NativePointer = NULL;
  battleButton: NativePointer = NULL;

  popup: NativePointer;
  closeButton: NativePointer;

  constructor() {
    this.popup = malloc(1024);
    let scFile = createStringObject("sc/natesworks.sc");
    let exportName = createStringObject("nw_battlesettings");

    popupBaseConstructor(this.popup, scFile, exportName, 1, 0);
    // can't name it better I got these value from scid link window
    this.popup
      .add(Offsets.VTablePointer)
      .writePointer(base.add(Offsets.VTablePointerValue));
    this.popup
      .add(Offsets.VTablePointer2)
      .writePointer(base.add(Offsets.VTablePointer2Value));

    for (let i = 0; i < 30; i++) {
      this.popup.add(0x98).add(i).writeU8(0);
    }

    this.closeButton = addGameButton(
      this.popup,
      Memory.allocUtf8String("close"),
      1,
    );

    /*
    addGameButton(popup, Memory.allocUtf8String("TID_INFINITEELIXIR"), 1);
    addGameButton(popup, Memory.allocUtf8String("infiniteelixir_button_on"), 1);
    */
  }

  createSettingsButton(settingsPopup: NativePointer) {
    this.settingsButton = addGameButton(
      settingsPopup,
      Memory.allocUtf8String("battlesettings_button"),
      1,
    );
    let setTextOffset = this.settingsButton
      .readPointer()
      .add(Offsets.GameButtonSetText)
      .readPointer();
    let setText = new NativeFunction(setTextOffset, "void", [
      "pointer",
      "pointer",
      "pointer",
    ]);
    let textField = Memory.allocUtf8String("txt");
    let text = getString(createStringObject("TID_BATTLESETTINGS"));
    setText(this.settingsButton, textField, text);
  }

  createBattleButton(combatHUD: NativePointer) {
    const stageWidth = base.add(Offsets.BattleScreenStageWidth).readFloat();
    const stageHeight = base.add(Offsets.BattleScreenStageHeight).readFloat();
    const button = malloc(200);

    let movieclip = getMovieClip(
      Memory.allocUtf8String("sc/natesworks.sc"),
      Memory.allocUtf8String("nw_battlesettings_button"),
    );
    setPixelSnappedXY(
      movieclip,
      stageWidth * 0.5 - getWidth(movieclip) / 2,
      stageHeight - 1.5 * getHeight(movieclip),
    );
    spriteAddChild(combatHUD, movieclip);
    gameButtonContructor(button);
    let movieclip2 = getMovieClipByName(
      movieclip,
      Memory.allocUtf8String("battlesettings_button"),
    );
    setDisplayObject(button, movieclip2, 1);
    spriteAddChild(movieclip, button);
    Logger.debug("Added nw_battlesettings_button");
  }

  show() {
    showPopup(getGUIInstance(), this.popup, 1, 1, 1);
  }
}
