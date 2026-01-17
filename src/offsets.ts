import { getDocumentsDirectory } from "./util.js";
import { version } from "version";

export let Offsets: Record<string, string>;

export function setupOffsets() {
  const offsets = version.offsets;
  Offsets = Object.fromEntries(
    Object.entries(offsets).map(([k, v]) => [k, String(v)]),
  );
}
