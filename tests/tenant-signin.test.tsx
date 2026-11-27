import { describe, expect, it } from "vitest";
import { clientIdFor, inlineRunCommand, runnableScript, signInBlockReason } from "../src/components/tenantSignIn";
import { collectAccess } from "../src/lib/accessCollect";
import { graphGetter } from "../src/lib/postureCollect";

const LAB = "7a1b2c3d-1111-4a2b-8c3d-000000000001";
const PROD = "7a1b2c3d-1111-4a2b-8c3d-000000000002";
const CID = "7a1b2c3d-1111-4a2b-8c3d-000000000006";

describe("client ID per tenant", () => {
  it("brings back each tenant's own client ID", () => {
    const map = { [LAB]: CID };
    expect(clientIdFor(LAB, map, "x")).toBe(CID);
    expect(clientIdFor(LAB.toUpperCase(), map, "x")).toBe(CID);
    expect(clientIdFor(PROD, map, CID)).toBe("");
  });
  it("uses the older shared value until any tenant has its own", () => {
    expect(clientIdFor(PROD, {}, CID)).toBe(CID);
  });
});

describe("why sign-in is greyed out", () => {
  it("names the missing box", () => {
    expect(signInBlockReason(null, "", "")).toMatch(/Directory \(tenant\) ID/);
    expect(signInBlockReason(null, LAB, "")).toMatch(/Client ID of F360-Discovery.*App registrations > All applications > F360-Discovery/);
    expect(signInBlockReason(null, LAB, "nope")).toMatch(/must be a GUID/);
    expect(signInBlockReason(null, LAB, CID)).toBeNull();
    expect(signInBlockReason(null, LAB, CID, "Type a person")).toBe("Type a person");
    expect(signInBlockReason("Blocked here", LAB, CID)).toBe("Blocked here");
  });
});

describe("run without downloading", () => {
  const script = "<#\n.SYNOPSIS\n  Test ✓\n#>\n#Requires -Version 7.2\n[CmdletBinding()]\nparam([string]$TenantId)\n'hi'\n";
  it("drops #Requires and carries the whole script on one line", () => {
    expect(runnableScript(script)).not.toMatch(/#Requires/);
    const line = inlineRunCommand(script, `-TenantId ${LAB}`);
    expect(line).not.toContain("\n");
    expect(line).toMatch(/PSVersion\.Major -lt 7/);
    expect(line.endsWith(`-TenantId ${LAB} }`)).toBe(true);
    const b64 = /FromBase64String\('([^']+)'\)/.exec(line)![1];
    expect(Buffer.from(b64, "base64").toString("utf8")).toBe(runnableScript(script));
  });
});

describe("Graph errors", () => {
  it("name the request that failed", async () => {
    const f = (async () => new Response(JSON.stringify({ error: { code: "Authorization_RequestDenied", message: "Insufficient privileges to complete the operation." } }), { status: 403 })) as typeof fetch;
    await expect(graphGetter("t", f)("organization?$select=id")).rejects.toThrow(/403 Authorization_RequestDenied: Insufficient privileges to complete the operation\. \(GET v1\.0\/organization\)/);
  });
  it("How access ends carries on when the organisation read is denied", async () => {
    const get = async (path: string) => {
      if (path.startsWith("organization")) throw Object.assign(new Error("403 Authorization_RequestDenied (GET v1.0/organization)"), { status: 403 });
      return { value: [] };
    };
    const s = await collectAccess(get, PROD);
    expect(s.tenant.id).toBe(PROD);
    expect(s.apps).toEqual([]);
  });
  it("says which permission is missing when enterprise apps are denied", async () => {
    const get = async (path: string) => {
      if (path.startsWith("servicePrincipals")) throw Object.assign(new Error("403 Authorization_RequestDenied"), { status: 403 });
      return { value: [] };
    };
    await expect(collectAccess(get, PROD)).rejects.toThrow(/Application\.Read\.All/);
  });
});
