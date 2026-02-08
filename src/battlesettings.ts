import {
  addGameButton,
  base,
  getGUIInstance,
  getTextFieldByName,
  malloc,
  popupBaseConstructor,
  showPopup,
} from "./definitions";
import { Offsets } from "./offsets";
import { createStringObject } from "./util";

export class BattleSettings {
  popup: NativePointer = NULL;

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

    addGameButton(this.popup, Memory.allocUtf8String("close"), 1);

    /*
    addGameButton(popup, Memory.allocUtf8String("TID_INFINITEELIXIR"), 1);
    addGameButton(popup, Memory.allocUtf8String("infiniteelixir_button_on"), 1);
    */
  }

  show() {
    showPopup(getGUIInstance(), this.popup, 1, 1, 1);
  }
}
