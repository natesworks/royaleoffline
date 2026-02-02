import { getDocumentsDirectory } from "./util.js";
import { offsets } from "offsets";

export let Offsets: Record<string, string>;

export function setupOffsets() {
  Offsets = Object.fromEntries(
    Object.entries(offsets).map(([k, v]) => [k, String(v)]),
  );
}
