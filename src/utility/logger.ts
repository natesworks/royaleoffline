// Parts of this code was taken from NBS v44 and were AI generated

function getTimestamp(): string {
  const d = new Date();
  const dd = String(d.getDate()).padStart(2, "0");
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const yy = String(d.getFullYear()).slice(2);
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `[${dd}/${mm}/${yy} ${hh}:${mi}:${ss}]`;
}

function format(args: any[]): string {
  return args
    .map((a) => {
      if (typeof a === "string") return a;

      if (a instanceof ArrayBuffer) {
        return Array.from(new Uint8Array(a))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(" ");
      }

      if (a instanceof Uint8Array) {
        return Array.from(a)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(" ");
      }

      try {
        return String(a);
      } catch {
        return "[object]";
      }
    })
    .join(" ");
}

// TODO: logging to file and logcat
/*
Log levels:
0 - Error, warn, info, debug, verbose
1 - Error, warn, info, debug
2 - Error, warn, info
3 - Error, warn
4 - Error
5 - None
*/
export class Logger {
  static error(...args: any[]): void {
    const msg = format(args);
    const line = `${getTimestamp()} [ERROR] ${msg}`;
    console.log(line);
  }

  static warn(...args: any[]): void {
    const msg = format(args);
    const line = `${getTimestamp()} [WARN] ${msg}`;
    console.log(line);
  }

  static info(...args: any[]): void {
    const msg = format(args);
    const line = `${getTimestamp()} [INFO] ${msg}`;
    console.log(line);
  }

  static debug(...args: any[]): void {
    const msg = format(args);
    const line = `${getTimestamp()} [DEBUG] ${msg}`;
    console.log(line);
  }

  static verbose(...args: any[]): void {
    const msg = format(args);
    const line = `${getTimestamp()} [VERBOSE] ${msg}`;
    console.log(line);
  }
}
