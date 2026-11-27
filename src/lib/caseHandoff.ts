// Carries what Detections has loaded to Investigate when the person clicks "Investigate this person".
// In memory only: it lasts until the page reloads, like the logs on Detections.
import type { LoadedLogs } from "../detections/events";
import type { Hit } from "../detections/rules";

export interface Handoff {
  logs: LoadedLogs;
  hits: Hit[];
  label: string;
}
let pending: Handoff | null = null;

export function handOff(h: Handoff) {
  pending = h;
}
/** Returns the hand-off once, then forgets it. */
export function takeHandoff(): Handoff | null {
  const h = pending;
  pending = null;
  return h;
}
