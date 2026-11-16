// @vitest-environment node
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
// @ts-ignore: plain JavaScript module run by Node in the lab
import { createScimServer, applyPatch, parseFilter } from "../lab/scim/server.mjs";
import { parseScim, checkScim } from "../src/lib/scim";

const TOKEN = "lab-token-0123456789abcdef";
let dir: string;
let server: any;
let base: string;

const call = async (method: string, path: string, body?: unknown, auth = true) => {
  const r = await fetch(base + path, {
    method,
    headers: { ...(auth ? { Authorization: `Bearer ${TOKEN}` } : {}), "Content-Type": "application/scim+json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  return { status: r.status, body: text ? JSON.parse(text) : null };
};

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "f360-scim-"));
  server = createScimServer({ token: TOKEN, dataDir: join(dir, "data"), logDir: join(dir, "logs"), quiet: true });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/scim`;
});
afterAll(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

const entraUser = {
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
  externalId: "lab.user1",
  userName: "lab.user1@contoso.onmicrosoft.com",
  active: true,
  displayName: "Lab User 1",
  emails: [{ primary: true, type: "work", value: "lab.user1@contoso.onmicrosoft.com" }],
};

test("lab SCIM app rejects a missing token with a SCIM 401", async () => {
  const r = await call("GET", "/Users", undefined, false);
  expect(r.status).toBe(401);
  expect(r.body.schemas[0]).toContain("Error");
});

test("lab SCIM app follows Entra's create, lookup and disable sequence", async () => {
  const probe = await call("GET", `/Users?filter=${encodeURIComponent('userName eq "nobody@x"')}`);
  expect(probe.status).toBe(200);
  expect(probe.body.totalResults).toBe(0);

  const created = await call("POST", "/Users", entraUser);
  expect(created.status).toBe(201);
  expect((await call("POST", "/Users", { ...entraUser, userName: entraUser.userName.toUpperCase() })).status).toBe(409);

  const found = await call("GET", `/Users?filter=${encodeURIComponent('userName eq "LAB.USER1@contoso.onmicrosoft.com"')}`);
  expect(found.body.totalResults).toBe(1);

  const patched = await call("PATCH", `/Users/${created.body.id}`, {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations: [{ op: "Replace", path: "active", value: "False" }],
  });
  expect(patched.status).toBe(200);
  expect(patched.body.active).toBe(false);
  expect((await call("GET", "/Users/does-not-exist")).status).toBe(404);
});

test("lab SCIM app logs can be pasted into the SCIM checker", () => {
  const files = readdirSync(join(dir, "logs")).filter((f) => f.includes("-POST-201"));
  expect(files.length).toBe(1);
  const text = readFileSync(join(dir, "logs", files[0]), "utf8");
  expect(text).not.toContain(TOKEN);
  const [reqPart, resPart] = text.split("----- response -----");
  const req = parseScim(reqPart);
  expect(req.method).toBe("POST");
  expect(req.kind).toBe("user");
  const res = parseScim(resPart);
  expect(res.status).toBe(201);
  expect(checkScim(res, { signInId: "lab.user1@contoso.onmicrosoft.com" }).some((f: { severity: string }) => f.severity === "critical")).toBe(false);
});

test("applyPatch handles Entra's path forms", () => {
  const out = applyPatch(
    { userName: "a@b", emails: [{ type: "work", value: "a@b" }] },
    {
      Operations: [
        { op: "Replace", path: 'emails[type eq "work"].value', value: "c@d" },
        { op: "Add", path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", value: "7" },
        { op: "Add", value: { "name.givenName": "Ann", title: "Tester" } },
      ],
    },
  );
  expect(out.emails[0].value).toBe("c@d");
  expect(out["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].employeeNumber).toBe("7");
  expect(out.name.givenName).toBe("Ann");
  expect(out.title).toBe("Tester");
  expect(() => parseFilter('userName gt "a"')).toThrow();
});
