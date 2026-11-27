import { renderToStaticMarkup } from "react-dom/server";
import { Ctx, type AppCtx } from "../src/components/ui";
import UserLookup from "../src/views/UserLookup";
import { ACCESS_SNAPSHOT_PREF } from "../src/views/AccessEnds";
import { ACTIVITY_PREF } from "../src/views/Activity";
import { sampleUserAccess, SAMPLE_PEOPLE } from "../src/data/sampleUserAccess";
import { sampleAccess } from "../src/data/sampleAccess";
import { sampleActivityFile } from "../src/data/sampleActivity";
import { emptySummary, foldActivity, readActivityFile } from "../src/lib/activity";

const ctx = (over: Partial<AppCtx> = {}): AppCtx => ({ store: null, tenants: [], apps: [], loading: false, go: () => {}, params: {}, toast: () => {}, loadExamples: async () => {}, ...over });
const render = (params: Record<string, string> = {}) => renderToStaticMarkup(<Ctx.Provider value={ctx({ params })}><UserLookup /></Ctx.Provider>);
afterEach(() => localStorage.clear());

describe("User lookup page", () => {
  it("offers PowerShell, sign-in and sample data", () => {
    const out = render();
    expect(out).toContain("<h1>User lookup</h1>");
    expect(out).toContain("Download Export-F360UserAccess.ps1");
    expect(out).toContain("Read from Entra");
    expect(out).toContain("Try with sample data");
  });

  it("shows every app for a saved read, longest exposure first", () => {
    const s = sampleUserAccess(SAMPLE_PEOPLE[1])!;
    localStorage.setItem("f360:pref:lookup:reads", JSON.stringify({ [SAMPLE_PEOPLE[1]]: s }));
    localStorage.setItem("f360:pref:" + ACCESS_SNAPSHOT_PREF, JSON.stringify(sampleAccess()));
    localStorage.setItem("f360:pref:" + ACTIVITY_PREF, JSON.stringify({ ...foldActivity(emptySummary(), readActivityFile("s.json", JSON.stringify(sampleActivityFile()))), example: true }));
    const out = render({ q: SAMPLE_PEOPLE[1] });
    expect(out).toContain("Sam Leaver");
    expect(out).toContain("Every app, longest exposure first");
    expect(out).toContain("HR Hub");
    expect(out).toContain("SAM-MACBOOK");
    expect(out).toContain("Example");
  });
});
