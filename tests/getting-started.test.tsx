// Getting started (2026-11-16): a GETTING STARTED rail section above MANAGE, its page is what Federation 360 opens on, and every
// step and situation points at a page that exists. Overview stays the health view and links here instead of repeating it.
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { Ctx, type AppCtx } from "../src/components/ui";
import GettingStarted from "../src/views/GettingStarted";
import Overview from "../src/views/Overview";
import { ASK_YOUR_TEAM, BASICS, PHASES, SITUATIONS, START_STEPS } from "../src/data/gettingStarted";

const app = readFileSync("src/App.tsx", "utf8");
const routeIds = [...app.matchAll(/\{ id: "([a-z]+)", label:/g)].map((m) => m[1]);

const ctx = (over: Partial<AppCtx> = {}): AppCtx => ({
  store: null, tenants: [], apps: [], loading: false, go: () => {}, params: {}, toast: () => {}, loadExamples: async () => {}, ...over,
});
const render = (el: JSX.Element, over?: Partial<AppCtx>) => renderToStaticMarkup(<Ctx.Provider value={ctx(over)}>{el}</Ctx.Provider>);

describe("Getting started", () => {
  it("is the first rail section, above Manage, and the default page", () => {
    expect(app).toMatch(/const groups = \["Getting started", "Manage", "Troubleshoot", "Learn"\]/);
    expect(routeIds[0]).toBe("start");
    expect(app).toMatch(/const DEFAULT_ROUTE = "start";/);
    expect(app).toMatch(/\? h : DEFAULT_ROUTE;/);
  });

  it("every step and situation opens a page that exists", () => {
    for (const s of [...START_STEPS, ...SITUATIONS]) expect(routeIds, s.open.label).toContain(s.open.route);
    for (const p of PHASES) expect(START_STEPS.some((s) => s.phase === p.id)).toBe(true);
    expect(new Set(START_STEPS.map((s) => s.id)).size).toBe(START_STEPS.length);
  });

  it("explains SAML, OIDC and SCIM and renders the path", () => {
    expect(BASICS.map((b) => b.id)).toEqual(["saml", "oidc", "scim"]);
    const out = render(<GettingStarted />);
    expect(out).toContain("<h1>Getting started</h1>");
    expect(out).toContain("Start step 1");
    for (const s of START_STEPS) expect(out).toContain(s.open.label);
    expect(out).toContain(`0 of ${START_STEPS.length} done`);
    expect(ASK_YOUR_TEAM.length).toBeGreaterThan(3);
  });

  it("keeps job and career content out of the app", () => {
    const text = readFileSync("src/data/gettingStarted.ts", "utf8") + readFileSync("src/views/GettingStarted.tsx", "utf8");
    expect(text).not.toMatch(/job skill|interview|résumé|resume|career|hiring/i);
  });
});

describe("Overview for a first-time user", () => {
  it("points new users at Getting started and no longer repeats a start-here list", () => {
    const out = render(<Overview />);
    expect(out).toContain("New to SAML, OIDC and SCIM?");
    expect(out).toContain("Open Getting started");
    expect(out).not.toContain("New to this? Start here");
  });

  it("an empty inventory offers Discover first", () => {
    const out = render(<Overview />);
    expect(out).toContain("Nothing here yet");
    expect(out).toContain("Read my apps with Discover");
  });
});
