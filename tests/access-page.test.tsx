// How access ends (identity access plan, Phase 1): the page renders all three inputs before a scan, the sample shows every
// state, and the Inventory drawer shows the same facts plus the declared app profile.
import { renderToStaticMarkup } from "react-dom/server";
import { Ctx, type AppCtx } from "../src/components/ui";
import AccessEnds, { ACCESS_SNAPSHOT_PREF } from "../src/views/AccessEnds";
import Inventory from "../src/views/Inventory";
import { sampleAccess } from "../src/data/sampleAccess";
import { exampleData } from "../src/data/seed";

const ctx = (over: Partial<AppCtx> = {}): AppCtx => ({
  store: null, tenants: [], apps: [], loading: false, go: () => {}, params: {}, toast: () => {}, loadExamples: async () => {}, ...over,
});
const render = (el: JSX.Element, over?: Partial<AppCtx>) => renderToStaticMarkup(<Ctx.Provider value={ctx(over)}>{el}</Ctx.Provider>);

afterEach(() => localStorage.clear());

describe("How access ends page", () => {
  it("offers PowerShell, sign-in and sample data before a scan", () => {
    const out = render(<AccessEnds />);
    expect(out).toContain("<h1>How access ends</h1>");
    expect(out).toContain("Download Export-F360Access.ps1");
    expect(out).toContain("Sign in and read");
    expect(out).toContain("Try with sample data");
    expect(out).toContain("Synchronization.Read.All");
  });

  it("shows the sample scan with every SCIM state and the made-up flag", () => {
    localStorage.setItem("f360:pref:" + ACCESS_SNAPSHOT_PREF, JSON.stringify(sampleAccess()));
    const { tenants, apps } = exampleData();
    const out = render(<AccessEnds />, { tenants, apps });
    expect(out).toContain("made-up sample");
    for (const s of ["Quarantined", "Healthy", "Running, some errors", "No SCIM"]) expect(out).toContain(s);
    expect(out).toContain("Every 12 hours; every time for 4 roles");
    expect(out).toContain("480 to 480".replace("480 to 480", "8 hours"));
  });
});

describe("Inventory drawer", () => {
  it("shows How access ends and the declared app profile for a matched app", () => {
    localStorage.setItem("f360:pref:" + ACCESS_SNAPSHOT_PREF, JSON.stringify(sampleAccess()));
    const { tenants, apps } = exampleData();
    const out = render(<Inventory />, { tenants, apps, params: { app: "ex-expenses" } });
    expect(out).toContain("How access ends · from the scan of");
    expect(out).toContain("Declared app profile");
    expect(out).toContain("Ends sessions on SCIM disable");
    expect(out).toContain('value="480"');
  });

  it("says how to get a scan when none matches", () => {
    const { tenants, apps } = exampleData();
    const out = render(<Inventory />, { tenants, apps, params: { app: "ex-expenses" } });
    expect(out).toContain("No access scan matches this app yet.");
  });
});
