import { renderToStaticMarkup } from "react-dom/server";
import { Ctx, type AppCtx } from "../src/components/ui";
import Activity, { ACTIVITY_PREF } from "../src/views/Activity";
import { emptySummary, foldActivity, readActivityFile } from "../src/lib/activity";
import { sampleActivityFile } from "../src/data/sampleActivity";

const ctx = (over: Partial<AppCtx> = {}): AppCtx => ({ store: null, tenants: [], apps: [], loading: false, go: () => {}, params: {}, toast: () => {}, loadExamples: async () => {}, ...over });
const render = (el: JSX.Element) => renderToStaticMarkup(<Ctx.Provider value={ctx()}>{el}</Ctx.Provider>);
afterEach(() => localStorage.clear());

describe("Activity page", () => {
  it("offers files, PowerShell, sign-in and sample data", () => {
    const out = render(<Activity />);
    expect(out).toContain("<h1>Activity</h1>");
    expect(out).toContain("Download Export-F360Activity.ps1");
    expect(out).toContain("Sign in and read");
    expect(out).toContain("Try with sample data");
    expect(out).toContain("Download JSON");
  });

  it("shows cadence, workloads and people from a saved summary", () => {
    const sum = { ...foldActivity(emptySummary(), readActivityFile("s.json", JSON.stringify(sampleActivityFile()))), example: true };
    localStorage.setItem("f360:pref:" + ACTIVITY_PREF, JSON.stringify(sum));
    const out = render(<Activity />);
    expect(out).toContain("Refresh cadence per app");
    expect(out).toContain("Partner Portal");
    expect(out).toContain("Payroll sync job");
    expect(out).toContain("sam.leaver@contoso.example");
    expect(out).toContain("Sessions revoked");
    expect(out).toContain("made-up sample");
  });
});
