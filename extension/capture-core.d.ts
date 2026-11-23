// Types for capture-core.js, so the tests can use it from TypeScript.
import type { HarEntry } from "../src/lib/har";

export const IDP_HOSTS: RegExp[];
export const FLOW_GAP_MS: number;
export const MAX_FLOWS: number;
export const MAX_HOPS: number;
export interface CapturedRequest { url: string; method: string; formData?: Record<string, string[]>; formText?: string; authorization?: string; clientRequestId?: string; time?: number }
export interface CaptureFlow { id: string; tabId: number; tabTitle: string; startedAt: string; updatedAt: number; done?: boolean; entries: HarEntry[] }
export interface CaptureState { flows: CaptureFlow[] }
export function isIdpHost(host: string): boolean;
export function formText(formData?: Record<string, string[]>): string | undefined;
export function toEntry(req: CapturedRequest, res: { status?: number; redirectUrl?: string; bodyText?: string; mimeType?: string; requestId?: string }): HarEntry;
export function mightMatter(url: string, method: string, formData?: Record<string, string[]>): boolean;
export function classify(entry: HarEntry): "signin" | "api" | null;
export function phase(entry: HarEntry): "start" | "return" | "silent" | null;
export function openFlow(state: CaptureState, tabId: number, now: number): CaptureFlow | null;
export const PAIR_MS: number;
export function addTokenResponse(state: CaptureState, msg: { tabId: number; tabTitle?: string; url: string; request: string; status: number; body: string; now: number }): CaptureFlow | null;
export function addHop(state: CaptureState, hop: { tabId: number; tabTitle?: string; entry: HarEntry; kind: "signin" | "api" | null; now: number }): CaptureFlow | null;
