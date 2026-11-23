// Learn page: the Device SSO (macOS Platform SSO, Windows PRT) topic.
import { readFileSync } from "node:fs";
import { DEVICE_SSO_TITLE, DEVICE_FLOWS, DEVICE_SSO_FACTS, DEVICE_SSO_CHECKS, DEVICE_SSO_PORTALS, DEVICE_SSO_SOURCES } from "../src/data/deviceSso";
import { GLOSSARY } from "../src/data/learn";

describe("Device SSO Learn topic", () => {
  it("has the agreed title and is shown on the Learn page", () => {
    expect(DEVICE_SSO_TITLE).toBe("Device SSO (macOS Platform SSO, Windows PRT)");
    expect(readFileSync("src/views/Learn.tsx", "utf8")).toContain("<DeviceSso />");
  });

  it("covers macOS Platform SSO, Windows PRT and browser SSO into SAML/OIDC apps", () => {
    expect(DEVICE_FLOWS.map((f) => f.id)).toEqual(["macos-psso", "windows-prt", "browser-prt"]);
    for (const f of DEVICE_FLOWS) {
      expect(f.steps.length).toBeGreaterThan(4);
      for (const s of f.steps) {
        expect(s.from).toBeLessThan(f.actors.length);
        expect(s.to).toBeLessThan(f.actors.length);
      }
      expect(f.watch.length).toBeGreaterThan(0);
    }
  });

  it("states the key facts: no prompt, apps never get the PRT, FileVault, Kerberos", () => {
    const text = JSON.stringify(DEVICE_SSO_FACTS) + JSON.stringify(DEVICE_FLOWS);
    for (const needle of ["no prompt", "never get the PRT", "FileVault", "Kerberos", "Secure Enclave", "TPM", "Intune"]) expect(text).toContain(needle);
  });

  it("gives device checks with success criteria", () => {
    expect(DEVICE_SSO_CHECKS.map((c) => c.body)).toEqual(["app-sso platform -s", "dsregcmd /status"]);
    for (const c of DEVICE_SSO_CHECKS) expect(c.success.length).toBeGreaterThan(20);
  });

  it("links only to Microsoft portals and Microsoft pages over https", () => {
    for (const p of DEVICE_SSO_PORTALS) expect(p.url).toMatch(/^https:\/\/(entra|intune)\.microsoft\.com\/#view\//);
    for (const s of DEVICE_SSO_SOURCES) expect(s.url).toMatch(/^https:\/\/(learn\.microsoft\.com|techcommunity\.microsoft\.com)\//);
  });

  it("adds the device SSO terms to the glossary", () => {
    const terms = GLOSSARY.map((g) => g.term);
    for (const t of ["Primary Refresh Token (PRT)", "Platform SSO (macOS)", "Microsoft Enterprise SSO plug-in", "Web Account Manager (WAM)"]) expect(terms).toContain(t);
  });

  it("keeps job and career content out of the app", () => {
    const src = readFileSync("src/data/deviceSso.ts", "utf8").toLowerCase();
    for (const w of ["job skill", "interview", "resume", "career"]) expect(src).not.toContain(w);
  });
});
