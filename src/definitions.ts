import { Offsets } from "./offsets.js";
import { isAndroid } from "./platform.js";
import { getDocumentsDirectory, getPackageName } from "./util.js";
import { Logger } from "./utility/logger.js";

export let base = NULL;

export const libc = isAndroid
  ? Process.getModuleByName("libc.so")
  : Process.getModuleByName("libSystem.B.dylib");

export const malloc = new NativeFunction(
  libc.getExportByName("malloc"),
  "pointer",
  ["uint"],
);

export const mkdir = new NativeFunction(libc.getExportByName("mkdir"), "int", [
  "pointer",
  "int",
]);

export let documentsDirectory: string;
export let pkgName: string;

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

export let assetManagerPtr: NativePointer;

export let startTrainingCampMatch:
  | NativeFunction<void, [NativePointerValue]>
  | ((arg0: any) => void);

export let loadAsset: NativeFunction<void, [NativePointerValue]>;
export let getJSONObject: NativeFunction<NativePointer, [NativePointerValue]>;
export let getJSONNumber: NativeFunction<
  NativePointer,
  [NativePointerValue, NativePointerValue]
>;
export let getIntValue: NativeFunction<number, [NativePointerValue]>;

export function load() {
  pkgName = getPackageName();
  documentsDirectory = getDocumentsDirectory();

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

  loadAsset = new NativeFunction(base.add(Offsets.LoadAsset), "void", [
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
}

export function setBase(ptr: NativePointer) {
  base = ptr;
}

export function setAssetManager(ptr: NativePointer) {
  assetManagerPtr = ptr;
}
