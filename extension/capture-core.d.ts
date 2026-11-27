// Types for capture-core.js, so the tests can use it from TypeScript.
import type { HarEntry } from "../src/lib/har";

export const IDP_HOSTS: RegExp[];
export const FLOW_GAP_MS: number;
export const MAX_FLOWS: number;
export const MAX_HOPS: number;
export interface CapturedRequest { url: string; method: string; formData?: Record<string, string[]>; formText?: string; authorization?: string; clientRequestId?: string; time?: number }
export interface CaptureFlow { id: string; tabId: number; tabTitle: string; startedAt: string; updatedAt: number; done?: boolean; entries: HarEntry[] }
export interface CaptureState { flows: CaptureFlow[] }
export const F360_ORIGINS: string[];
export const F360_SITE: string;
export const SHOWN_FIELDS: string[];
export const SECRET_FIELDS: string[];
export const REPLY_FIELDS: string[];
export const PRESENT: string;
export function isIdpHost(host: string): boolean;
export function isF360Page(url: unknown): boolean;
export function safeForm(url: string, formData?: Record<string, string[]>): Record<string, string[]> | undefined;
export function safeFormText(url: string, text?: string | null): string | undefined;
export function safeRequestUrl(url: string, samlInForm?: boolean): string;
export function safeTokenReply(body: string): string;
export function scrubEntry(entry: HarEntry): HarEntry;
export function scrubState(state: unknown): CaptureState;
export function formText(formData?: Record<string, string[]>): string | undefined;
export function toEntry(req: CapturedRequest, res: { status?: number; redirectUrl?: string; bodyText?: string; mimeType?: string; requestId?: string }): HarEntry;
export function mightMatter(url: string, method: string, formData?: Record<string, string[]>): boolean;
export function classify(entry: HarEntry): "signin" | "api" | null;
export function phase(entry: HarEntry): "start" | "return" | "whole" | null;
export function openFlow(state: CaptureState, tabId: number, now: number): CaptureFlow | null;
export const PAIR_MS: number;
export function addTokenResponse(state: CaptureState, msg: { tabId: number; tabTitle?: string; url: string; request: string; status: number; body: string; now: number }): CaptureFlow | null;
export function addIdpError(state: CaptureState, msg: { tabId: number; tabTitle?: string; url: string; text: string; requestId?: string; correlationId?: string; now: number }): CaptureFlow | null;
export function appHost(url: string, from?: string | null, redirect?: string | null): string;
export function addHop(state: CaptureState, hop: { tabId: number; tabTitle?: string; entry: HarEntry; kind: "signin" | "api" | null; now: number }): CaptureFlow | null;
