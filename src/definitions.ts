import { BattleSettings } from "./battlesettings";
import { UserData } from "./userdata";
import { getDocumentsDirectory, getPackageName } from "./util";
import { base } from "./base";

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

export let userdata = new UserData();

export let battleSettings: BattleSettings;

export function load() {
  pkgName = getPackageName();
  documentsDirectory = getDocumentsDirectory();
  logFile = documentsDirectory + "/log.txt";
  battleSettings = new BattleSettings();
}

export type ButtonHandler = (ptr: NativePointer) => void;
export const buttonHandlers: Array<{
  ptr: NativePointer;
  handler: ButtonHandler;
}> = [];
