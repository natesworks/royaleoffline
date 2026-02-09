import { BattleSettings } from "./battlesettings.js";
import { DeckHelper, Decks } from "./deck.js";
import { Offsets } from "./offsets.js";
import { UserData } from "./userdata.js";
import { getDocumentsDirectory, getPackageName } from "./util.js";
import { Logger } from "./utility/logger.js";

export let base = NULL;

export const libc = Process.getModuleByName("libc.so");

export const malloc = new NativeFunction(
  libc.getExportByName("malloc"),
  "pointer",
  ["uint"],
);
export const mkdir = new NativeFunction(libc.getExportByName("mkdir"), "int", [
  "pointer",
  "int",
]);
export const getuid = new NativeFunction(
  libc.getExportByName("getuid"),
  "int",
  [],
);
export const access = new NativeFunction(
  libc.getExportByName("access"),
  "int",
  ["pointer", "int"],
);
export const unlink = new NativeFunction(
  libc.getExportByName("unlink"),
  "int",
  ["pointer"],
);

export let documentsDirectory: string;
export let pkgName: string;
export let logFile: string;

export let createMessageByType: (arg0: NativePointer, arg1: number) => any;
export let operator_new:
  | NativeFunction<NativePointer, [number]>
  | ((arg0: number) => {
      (): any;
      new (): any;
      writeByteArray: { (arg0: number[]): any; new (): any };
    });
export let messageManagerReceiveMessage:
  | NativeFunction<number, [NativePointerValue, NativePointerValue]>
  | ((arg0: NativePointer, arg1: any) => void);
export let messagingSend: NativeFunction<
  number,
  [NativePointerValue, NativePointerValue]
>;
export let stringCtor: NativeFunction<
  NativePointer,
  [NativePointerValue, NativePointerValue]
>;

export let getCSV: NativeFunction<NativePointer, [NativePointerValue]>;
export let getTable: NativeFunction<NativePointer, [NativePointerValue]>;
export let getColumnCount: NativeFunction<number, [NativePointerValue]>;
export let getRowCount: NativeFunction<number, [NativePointerValue]>;
export let getRowName: NativeFunction<NativePointer, [NativePointerValue]>;
export let getRowAt: NativeFunction<
  NativePointer,
  [NativePointerValue, number]
>;
export let getValueAt: NativeFunction<
  NativePointer,
  [NativePointerValue, number, number]
>;
export let getBooleanValueAt: NativeFunction<
  number,
  [NativePointerValue, number]
>;
export let getIntegerValueAt: NativeFunction<
  number,
  [NativePointerValue, number]
>;

export let startTrainingCampMatch:
  | NativeFunction<void, [NativePointerValue]>
  | ((arg0: any) => void);

export let loadAsset: NativeFunction<number, [NativePointerValue]>;
export let getJSONObject: NativeFunction<NativePointer, [NativePointerValue]>;
export let getJSONNumber: NativeFunction<
  NativePointer,
  [NativePointerValue, NativePointerValue]
>;
export let getIntValue: NativeFunction<number, [NativePointerValue]>;
export let showCenteredFloaterText: (
  arg0: NativePointer,
  arg1: NativePointer,
  arg2: number,
  arg3: number,
) => void;
export let addGameButton: NativeFunction<
  NativePointer,
  [NativePointerValue, NativePointerValue, number]
>;

export let popupBaseConstructor:
  | NativeFunction<
      NativePointer,
      [
        NativePointerValue,
        NativePointerValue,
        NativePointerValue,
        number,
        number,
      ]
    >
  | (() => void);
export let getTextFieldByName: NativeFunction<
  NativePointer,
  [NativePointerValue, NativePointerValue]
>;
export let showPopup: NativeFunction<
  void,
  [NativePointerValue, NativePointerValue, number, number, number]
>;
export let getGUIInstance: NativeFunction<NativePointer, []>;
export let getString: NativeFunction<NativePointer, [NativePointerValue]>;

export let userdata = new UserData();

export let battleSettings: BattleSettings;

export function load() {
  pkgName = getPackageName();
  documentsDirectory = getDocumentsDirectory();
  logFile = documentsDirectory + "/log.txt";

  createMessageByType = new NativeFunction(
    base.add(Offsets.CreateMessageByType),
    "pointer",
    ["pointer", "int"],
  );
  operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", [
    "uint",
  ]);
  messageManagerReceiveMessage = new NativeFunction(
    base.add(Offsets.ReceiveMessage),
    "int",
    ["pointer", "pointer"],
  );
  messagingSend = new NativeFunction(base.add(Offsets.Send), "bool", [
    "pointer",
    "pointer",
  ]);
  stringCtor = new NativeFunction(
    base.add(Offsets.StringConstructor),
    "pointer",
    ["pointer", "pointer"],
  );
  getCSV = new NativeFunction(base.add(Offsets.GetCSV), "pointer", ["pointer"]);
  getTable = new NativeFunction(base.add(Offsets.GetTable), "pointer", [
    "pointer",
  ]);
  getColumnCount = new NativeFunction(base.add(Offsets.GetColumnCount), "int", [
    "pointer",
  ]);
  getRowCount = new NativeFunction(base.add(Offsets.GetRowCount), "int", [
    "pointer",
  ]);
  getRowAt = new NativeFunction(base.add(Offsets.GetRowAt), "pointer", [
    "pointer",
    "int",
  ]);
  getValueAt = new NativeFunction(base.add(Offsets.GetValueAt), "pointer", [
    "pointer",
    "int",
    "int",
  ]);
  getRowName = new NativeFunction(base.add(Offsets.GetRowName), "pointer", [
    "pointer",
  ]);
  getBooleanValueAt = new NativeFunction(
    base.add(Offsets.GetBooleanValueAt),
    "bool",
    ["pointer", "int"],
  );
  getIntegerValueAt = new NativeFunction(
    base.add(Offsets.GetIntegerValueAt),
    "int",
    ["pointer", "int"],
  );

  startTrainingCampMatch = new NativeFunction(
    base.add(Offsets.StartTrainingCampMatch),
    "void",
    ["pointer"],
  );

  loadAsset = new NativeFunction(base.add(Offsets.LoadAsset), "bool", [
    "pointer",
  ]);
  getJSONObject = new NativeFunction(
    base.add(Offsets.GetJSONObject),
    "pointer",
    ["pointer"],
  );
  getJSONNumber = new NativeFunction(
    base.add(Offsets.GetJSONNumber),
    "pointer",
    ["pointer", "pointer"],
  );
  getIntValue = new NativeFunction(base.add(Offsets.GetIntValue), "int", [
    "pointer",
  ]);

  showCenteredFloaterText = new NativeFunction(
    base.add(Offsets.ShowCenteredFloaterText),
    "void",
    ["pointer", "pointer", "float", "long"],
  );

  addGameButton = new NativeFunction(
    base.add(Offsets.AddGameButton),
    "pointer",
    ["pointer", "pointer", "bool"],
  );

  popupBaseConstructor = new NativeFunction(
    base.add(Offsets.PopupBaseConstructor),
    "pointer",
    ["pointer", "pointer", "pointer", "bool", "bool"],
  );
  getTextFieldByName = new NativeFunction(
    base.add(Offsets.GetTextFieldByName),
    "pointer",
    ["pointer", "pointer"],
  );
  showPopup = new NativeFunction(base.add(Offsets.GUIShowPopup), "void", [
    "pointer",
    "pointer",
    "bool",
    "bool",
    "bool",
  ]);
  getGUIInstance = new NativeFunction(
    base.add(Offsets.GUIGetInstance),
    "pointer",
    [],
  );

  getString = new NativeFunction(base.add(Offsets.GetString), "pointer", [
    "pointer",
  ]);
}

export function setBase(ptr: NativePointer) {
  base = ptr;
}

export function initBattleSettings() {
  battleSettings = new BattleSettings();
}
