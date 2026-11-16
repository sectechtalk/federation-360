// Learn page: the lifecycle walkthrough (create, maintain, remove) and the removal of the job skills section.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { LIFECYCLES, SCENARIO, fillLab } from "../src/data/lifecycle";
import { PLAYBOOKS } from "../src/data/playbooks";
import { WIZARDS } from "../src/data/wizards";
import * as learn from "../src/data/learn";

const read = (f: string) => readFileSync(resolve(process.cwd(), f), "utf8");
const routes = [...read("src/App.tsx").matchAll(/\{ id: "([a-z]+)", label:/g)].map((m) => m[1]);

describe("lifecycle walkthrough", () => {
  it("covers SAML, OIDC/OAuth and SCIM, each with create, maintain and remove", () => {
    expect(LIFECYCLES.flatMap((l) => l.protocols).sort()).toEqual(["oauth", "oidc", "saml", "scim"]);
    for (const l of LIFECYCLES) {
      expect(l.stages.map((s) => s.id)).toEqual(["create", "maintain", "remove"]);
      for (const s of l.stages) expect(s.steps.length).toBeGreaterThan(0);
    }
  });

  it("every step says what success looks like and gives something to do", () => {
    for (const l of LIFECYCLES)
      for (const s of l.stages)
        for (const st of s.steps) {
          expect(st.success.length, st.title).toBeGreaterThan(10);
          expect(!!(st.clicks?.length || st.code), st.title).toBe(true);
        }
  });

  it("links only to pages, wizards and playbooks that exist", () => {
    const steps = LIFECYCLES.flatMap((l) => l.stages.flatMap((s) => s.steps));
    for (const st of steps.filter((x) => x.open)) {
      expect(routes, st.title).toContain(st.open!.route);
      if (st.open!.route === "playbooks") expect(PLAYBOOKS.map((p) => p.id)).toContain(st.open!.params?.id);
      if (st.open!.route === "wizards") expect(WIZARDS.map((w) => w.id)).toContain(st.open!.params?.id);
    }
  });

  it("PowerShell blocks start in the repo folder or set the tenant first", () => {
    for (const l of LIFECYCLES)
      for (const s of l.stages)
        for (const st of s.steps) if (st.code) expect(st.code.body, st.title).toMatch(/^(cd \$HOME\\federation-360|\$TenantId = )/);
  });

  it("fills in the lab tenant and domain, with clear placeholders when they're blank", () => {
    expect(fillLab("api://{tenant}/x lab.user1@{domain}", " 8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10 ", "lab.example")).toBe("api://8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10/x lab.user1@lab.example");
    expect(fillLab("{tenant} {domain}", "", "")).toBe("<lab tenant ID> <lab domain>");
    const all = JSON.stringify({ LIFECYCLES, SCENARIO });
    expect(fillLab(all, "t", "d")).not.toMatch(/\{(tenant|domain)\}/);
  });
});

describe("job skills section", () => {
  it("is not in the shipped app", () => {
    expect(Object.keys(learn)).not.toContain("SKILLS_MAP");
    expect(read("src/views/Learn.tsx")).not.toMatch(/Job skills|SKILLS_MAP|target role/);
  });
});
