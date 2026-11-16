import { useEffect, useMemo, useState } from "react";
import { Ctx, useToastState, type AppCtx } from "./components/ui";
import { useCollection, useStore } from "./lib/store";
import type { AppIntegration, Tenant } from "./lib/types";
import { exampleData } from "./data/seed";
import GettingStarted from "./views/GettingStarted";
import Overview from "./views/Overview";
import Inventory from "./views/Inventory";
import Wizards from "./views/Wizards";
import SamlTool from "./views/SamlTool";
import JwtTool from "./views/JwtTool";
import MetadataTool from "./views/MetadataTool";
import Playbooks from "./views/Playbooks";
import Learn from "./views/Learn";
import Lab from "./views/Lab";
import ScimTool from "./views/ScimTool";
import Discover from "./views/Discover";
import FlowTracer from "./views/FlowTracer";
import LiveTest from "./views/LiveTest";
import Connectivity from "./views/Connectivity";
import { AppSwitcher, NavIcon, NavSection, ThemeToggle, useNavDrawer } from "./360/Shell360";

const ROUTES = [
  { id: "start", label: "Start here", group: "Getting started", icon: "rocket", el: GettingStarted },
  { id: "overview", label: "Overview", group: "Manage", icon: "layout-dashboard", el: Overview },
  { id: "inventory", label: "Inventory", group: "Manage", icon: "boxes", el: Inventory },
  { id: "discover", label: "Discover", group: "Manage", icon: "compass", el: Discover },
  { id: "wizards", label: "Setup wizards", group: "Manage", icon: "wand-sparkles", el: Wizards },
  { id: "flowtracer", label: "Flow tracer", group: "Troubleshoot", icon: "radar", el: FlowTracer },
  { id: "livetest", label: "Live test", group: "Troubleshoot", icon: "test-tube", el: LiveTest },
  { id: "connectivity", label: "Connectivity test", group: "Troubleshoot", icon: "monitor-dot", el: Connectivity },
  { id: "saml", label: "SAML decoder", group: "Troubleshoot", icon: "file-code", el: SamlTool },
  { id: "jwt", label: "JWT decoder", group: "Troubleshoot", icon: "braces", el: JwtTool },
  { id: "scim", label: "SCIM checker", group: "Troubleshoot", icon: "users", el: ScimTool },
  { id: "metadata", label: "Metadata checker", group: "Troubleshoot", icon: "file-check", el: MetadataTool },
  { id: "playbooks", label: "Playbooks", group: "Troubleshoot", icon: "book-open", el: Playbooks },
  { id: "learn", label: "Learn", group: "Learn", icon: "graduation-cap", el: Learn },
  { id: "lab", label: "Build your lab", group: "Learn", icon: "flask-conical", el: Lab },
] as const;

// The page f-360 opens on when the address has no #page (or an unknown one).
const DEFAULT_ROUTE = "start";

const routeFromHash = () => {
  const h = location.hash.replace(/^#/, "");
  return ROUTES.some((r) => r.id === h) ? h : DEFAULT_ROUTE;
};

function Mark() {
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden="true">
      <circle cx="16" cy="16" r="13" fill="none" stroke="var(--accent)" strokeWidth="2.4" strokeDasharray="56 26" strokeLinecap="round" />
      <circle cx="16" cy="16" r="6.5" fill="none" stroke="var(--saml)" strokeWidth="2" />
      <circle cx="16" cy="16" r="2.2" fill="var(--oauth)" />
    </svg>
  );
}

export default function App() {
  const [route, setRoute] = useState(routeFromHash);
  const [params, setParams] = useState<Record<string, string>>({});
  const store = useStore();
  const t = useCollection<Tenant>(store, "tenants");
  const a = useCollection<AppIntegration>(store, "apps");
  const { msg, toast } = useToastState();
  const menuButton = useNavDrawer("rail");

  useEffect(() => {
    const on = () => setRoute(routeFromHash());
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);

  // In this browser (not signed in to a Claude artifact), seed examples once so the screens aren't empty.
  useEffect(() => {
    if (store?.kind !== "local" || t.rows === null || a.rows === null) return;
    let seeded = false;
    try {
      seeded = localStorage.getItem("f360:seeded") === "1";
    } catch {
      /* ignore */
    }
    if (!seeded && t.rows.length === 0 && a.rows.length === 0) {
      const d = exampleData();
      d.tenants.forEach((x) => store.put("tenants", x));
      d.apps.forEach((x) => store.put("apps", x));
      try {
        localStorage.setItem("f360:seeded", "1");
      } catch {
        /* ignore */
      }
    }
  }, [store, t.rows, a.rows]);

  const ctx: AppCtx = useMemo(
    () => ({
      store,
      tenants: [...(t.rows ?? [])].sort((x, y) => x.name.localeCompare(y.name)),
      apps: [...(a.rows ?? [])].sort((x, y) => x.name.localeCompare(y.name)),
      loading: !store || t.rows === null || a.rows === null,
      params,
      go: (r, p) => {
        setParams(p ?? {});
        if (location.hash !== "#" + r) location.hash = r;
        else setRoute(r);
        window.scrollTo({ top: 0 });
      },
      toast,
      loadExamples: async () => {
        if (!store) return;
        const d = exampleData();
        await Promise.all([...d.tenants.map((x) => store.put("tenants", x)), ...d.apps.map((x) => store.put("apps", x))]);
        toast("Example tenants and apps added");
      },
    }),
    [store, t.rows, a.rows, params],
  );

  const View = ROUTES.find((r) => r.id === route)!.el;
  const groups = ["Getting started", "Manage", "Troubleshoot", "Learn"];

  return (
    <Ctx.Provider value={ctx}>
      <div className="shell">
        <nav className="rail" id="rail" aria-label="Main">
          <div className="brand">
            <Mark />
            <div>
              <div className="brand-name">Federation 360</div>
              <div className="brand-sub">SAML · OIDC · OAuth · SCIM</div>
            </div>
          </div>
          <AppSwitcher current="f-360" />
          {groups.map((g) => (
            <NavSection key={g} title={g} current={ROUTES.some((r) => r.group === g && r.id === route)}>
              {ROUTES.filter((r) => r.group === g).map((r) => (
                <a key={r.id} className="nav-item" href={"#" + r.id} aria-current={route === r.id ? "page" : undefined} onClick={() => setParams({})}>
                  <NavIcon name={r.icon} />
                  {r.label}
                </a>
              ))}
            </NavSection>
          ))}
          <div className="rail-tools">
            <ThemeToggle />
          </div>
          <div className="rail-foot">
            <span>{store ? (store.kind === "cloud" ? "Inventory saved to this artifact" : "Inventory saved in this browser") : "Connecting storage…"}</span>
            <span>Tokens, assertions and SCIM messages you paste stay on this page. Discover talks only to Microsoft, read-only, and only when you sign in. Flow tracer reads HAR files in this tab; Live test talks only to Microsoft and the lab test app on your PC. Connectivity test results you drop in stay on this page.</span>
          </div>
        </nav>
        <main className="main">
          {menuButton}
          {(t.error || a.error) && (
            <div className="page" style={{ marginBottom: 16 }}>
              <div className="callout warn">The saved inventory couldn't be loaded: {t.error || a.error}. The tools still work; reload to try again.</div>
            </div>
          )}
          <View key={route + JSON.stringify(params)} />
        </main>
      </div>
      {msg && <div className="toast" role="status">{msg}</div>}
    </Ctx.Provider>
  );
}
