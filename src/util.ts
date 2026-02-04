import {
  base,
  malloc,
  mkdir,
  pkgName,
  stringCtor,
  getuid,
} from "./definitions";
import { Offsets } from "./offsets";
import { isAndroid } from "./platform";
import { Logger } from "./utility/logger";

const read = new NativeFunction(
  Process.getModuleByName(
    isAndroid ? "libc.so" : "libSystem.B.dylib",
  ).getExportByName("read"),
  "int",
  ["int", "pointer", "int"],
);
export const open = new NativeFunction(
  Process.getModuleByName(
    isAndroid ? "libc.so" : "libSystem.B.dylib",
  ).getExportByName("open"),
  "int",
  ["pointer", "int", "int"],
);
export const close = new NativeFunction(
  Process.getModuleByName(
    isAndroid ? "libc.so" : "libSystem.B.dylib",
  ).getExportByName("close"),
  "int",
  ["int"],
);

export function getPackageName() {
  const buf = Memory.alloc(4096);
  const fd = open(Memory.allocUtf8String("/proc/self/cmdline"), 0, 0);
  const n = read(fd, buf, 4096);
  close(fd);
  if (n <= 0) return "";
  const arr = new Uint8Array(buf.readByteArray(n) as ArrayBuffer);
  return String.fromCharCode(...arr).replace(/\0+$/, "");
}

export function getMessageManagerInstance(): NativePointer {
  return base.add(Offsets.MessageManagerInstance).readPointer();
}

export function getDocumentsDirectory(): string {
  const uid = getuid();
  const userId = Math.floor(uid / 100000);

  let path = `/storage/emulated/${userId}/Android/media/${pkgName}`;
  mkdir(Memory.allocUtf8String(path), 777);
  return path;
}

// cant use TextEncoder or TextDecoder in frida so skidded this thing
export function utf8ArrayToString(array: Uint8Array): string {
  let out = "",
    i = 0,
    len = array.length;
  while (i < len) {
    let c = array[i++];
    if (c < 128) {
      out += String.fromCharCode(c);
    } else if (c > 191 && c < 224) {
      let c2 = array[i++];
      out += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
    } else {
      let c2 = array[i++];
      let c3 = array[i++];
      out += String.fromCharCode(
        ((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63),
      );
    }
  }
  return out;
}

export function stringToUtf8Array(str: string): Uint8Array {
  let utf8 = [];
  for (let i = 0; i < str.length; i++) {
    let charcode = str.charCodeAt(i);
    if (charcode < 0x80) {
      utf8.push(charcode);
    } else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    } else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(
        0xe0 | (charcode >> 12),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f),
      );
    } else {
      i++;
      let surrogatePair =
        0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      utf8.push(
        0xf0 | (surrogatePair >> 18),
        0x80 | ((surrogatePair >> 12) & 0x3f),
        0x80 | ((surrogatePair >> 6) & 0x3f),
        0x80 | (surrogatePair & 0x3f),
      );
    }
  }
  return new Uint8Array(utf8);
}

function _decodeString(src: NativePointer): string | null {
  let len = src.add(4).readInt();
  if (len >= 8) {
    return src.add(8).readPointer().readUtf8String(len);
  }
  return src.add(8).readUtf8String(len);
}

export function decodeString(src: NativePointer): string {
  let res = _decodeString(src);
  if (!res) {
    Logger.error("Failed to decode string");
    throw new Error();
  }
  return res;
}

// TODO: don't leak memory
export function createStringObject(text: string) {
  let ptr = malloc(128);
  stringCtor(ptr, Memory.allocUtf8String(text));
  return ptr;
}

export function backtrace(ctx: CpuContext | undefined): void {
  const frames: any[] = Thread.backtrace(ctx, Backtracer.FUZZY);
  let lastAddr = "";
  let printed = 0;
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];
    const addrStr =
      typeof f === "string" || typeof f === "number" ? String(f) : f.toString();
    if (addrStr === lastAddr) continue;
    lastAddr = addrStr;
    const address = ptr(addrStr);
    const m = Process.findModuleByAddress(address);
    if (m) {
      const off = address.sub(m.base).toString();
      Logger.debug(
        `${printed.toString().padStart(2, " ")}  ${m.name} + ${off}  (${address})`,
      );
    } else {
      Logger.debug(
        `${printed.toString().padStart(2, " ")}  <unknown>  (${address})`,
      );
    }
    printed++;
  }
}
