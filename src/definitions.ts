import { Offsets, setupOffsets } from "./offsets.js";
import { isAndroid } from "./platform.js";
import { getDocumentsDirectory, getPackageName } from "./util.js";
import { version } from "version";

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
export let getRowAt:
  | NativeFunction<NativePointer, [NativePointerValue, number]>
  | (() => void);
export let getRowName;

export function load() {
  setupOffsets();
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
  getRowName = new NativeFunction(base.add(Offsets.GetRowName), "pointer", [
    "pointer",
  ]);
}

export function setBase(ptr: NativePointer) {
  base = ptr;
}
