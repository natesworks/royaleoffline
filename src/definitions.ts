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

export let createMessageByType: any;
export let operator_new: any;
export let messageManagerReceiveMessage: any;
export let messagingSend: any;

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
}

export function setBase(ptr: NativePointer) {
  base = ptr;
}
