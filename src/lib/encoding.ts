/** Base64 / base64url / deflate helpers that work in any modern browser. */

export function b64ToBytes(input: string): Uint8Array {
  let s = input.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export const bytesToB64url = (bytes: Uint8Array) =>
  bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const utf8 = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
export const toUtf8 = (s: string) => new TextEncoder().encode(s);

export function b64urlJson(segment: string): unknown {
  return JSON.parse(utf8(b64ToBytes(segment)));
}

export async function inflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("deflate-raw");
  const stream = new Response(bytes).body!.pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export async function deflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("deflate-raw");
  const stream = new Response(bytes).body!.pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function hex(bytes: ArrayBuffer | Uint8Array, sep = ""): string {
  return Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
    .join(sep);
}

export const normalizeThumbprint = (t: string) => t.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
