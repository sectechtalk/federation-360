/**
 * A minimal X.509 reader: enough DER parsing to show subject, issuer, validity
 * dates and thumbprints for certificates found in SAML metadata, SAML signatures
 * and JWKS x5c entries. It does not validate certificate chains.
 */
import { b64ToBytes, hex } from "./encoding";

interface Tlv {
  tag: number;
  start: number; // start of value
  end: number; // end of value
  headerStart: number;
}

function readTlv(buf: Uint8Array, pos: number): Tlv {
  const headerStart = pos;
  const tag = buf[pos++];
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[pos++];
  }
  return { tag, start: pos, end: pos + len, headerStart };
}

function children(buf: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = t.start;
  while (p < t.end) {
    const c = readTlv(buf, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

const OIDS: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.10045.2.1": "EC",
  "1.2.840.113549.1.1.5": "sha1WithRSA",
  "1.2.840.113549.1.1.11": "sha256WithRSA",
  "1.2.840.113549.1.1.12": "sha384WithRSA",
  "1.2.840.113549.1.1.13": "sha512WithRSA",
  "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
  "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
};

function oid(buf: Uint8Array, t: Tlv): string {
  const b = buf.subarray(t.start, t.end);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}

function str(buf: Uint8Array, t: Tlv): string {
  return new TextDecoder().decode(buf.subarray(t.start, t.end));
}

function name(buf: Uint8Array, t: Tlv): string {
  // Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value ANY }
  return children(buf, t)
    .flatMap((set) => children(buf, set))
    .map((atv) => {
      const [type, value] = children(buf, atv);
      const o = oid(buf, type);
      return `${OIDS[o] ?? o}=${str(buf, value)}`;
    })
    .join(", ");
}

function time(buf: Uint8Array, t: Tlv): Date {
  const s = str(buf, t);
  if (t.tag === 0x17) {
    // UTCTime YYMMDDHHMMSSZ
    const yy = parseInt(s.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, +s.slice(2, 4) - 1, +s.slice(4, 6), +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12)));
  }
  // GeneralizedTime YYYYMMDDHHMMSSZ
  return new Date(Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12), +s.slice(12, 14)));
}

export interface CertInfo {
  subject: string;
  issuer: string;
  notBefore: Date;
  notAfter: Date;
  serial: string;
  signatureAlgorithm: string;
  keyType: string;
  selfSigned: boolean;
  sha1: string;
  sha256: string;
  daysLeft: number;
  base64: string;
}

export async function parseCertificate(base64OrPem: string, now = new Date()): Promise<CertInfo> {
  const b64 = base64OrPem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  const der = b64ToBytes(b64);
  const cert = readTlv(der, 0);
  const [tbs, sigAlg] = children(der, cert);
  let fields = children(der, tbs);
  if (fields[0].tag === 0xa0) fields = fields.slice(1); // explicit version
  const [serialT, , issuerT, validityT, subjectT, spkiT] = fields;
  const [nb, na] = children(der, validityT);
  const spkiAlg = children(der, children(der, spkiT)[0])[0];
  const subject = name(der, subjectT);
  const issuer = name(der, issuerT);
  const notAfter = time(der, na);
  const [s1, s256] = await Promise.all([
    crypto.subtle.digest("SHA-1", der),
    crypto.subtle.digest("SHA-256", der),
  ]);
  return {
    subject,
    issuer,
    notBefore: time(der, nb),
    notAfter,
    serial: hex(der.subarray(serialT.start, serialT.end)),
    signatureAlgorithm: OIDS[oid(der, children(der, sigAlg)[0])] ?? oid(der, children(der, sigAlg)[0]),
    keyType: OIDS[oid(der, spkiAlg)] ?? oid(der, spkiAlg),
    selfSigned: subject === issuer,
    sha1: hex(s1),
    sha256: hex(s256),
    daysLeft: Math.floor((notAfter.getTime() - now.getTime()) / 86400000),
    base64: b64,
  };
}
