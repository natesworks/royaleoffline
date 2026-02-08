import {
  addGameButton,
  base,
  getGUIInstance,
  getTextFieldByName,
  malloc,
  popupBaseConstructor,
  showPopup,
} from "./definitions";
import { createStringObject } from "./util";

export class BattleSettings {
  popup: NativePointer = NULL;

  constructor() {
    let popup = malloc(1024);
    let scFile = createStringObject("sc/natesworks.sc");
    let exportName = createStringObject("nw_battlesettings");

    popupBaseConstructor(popup, scFile, exportName, 1, 0);
    popup.writePointer(base.add(0x502ca0));
    popup.add(0x48).writePointer(base.add(0x502d7c));
    let textField = getTextFieldByName(
      popup.add(0x50).readPointer(),
      Memory.allocUtf8String("TID_BATTLESETTINGS"),
    );
    for (let i = 0; i < 30; i++) {
      popup.add(0x98).add(i).writeU8(0);
    }
    popup.add(0x98).writePointer(textField);
    addGameButton(popup, Memory.allocUtf8String("close"), 1);

    /*
    addGameButton(popup, Memory.allocUtf8String("TID_INFINITEELIXIR"), 1);
    addGameButton(popup, Memory.allocUtf8String("infiniteelixir_button_on"), 1);
    */

    showPopup(getGUIInstance(), popup, 1, 1, 1);
  }

  show() {
    showPopup(getGUIInstance(), this.popup, 1, 1, 1);
  }
}
