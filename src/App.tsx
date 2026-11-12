import { useEffect, useMemo, useState } from "react";
import { Ctx, Icon, useToastState, type AppCtx } from "./components/ui";
import { useCollection, useStore } from "./lib/store";
import type { AppIntegration, Tenant } from "./lib/types";
import { exampleData } from "./data/seed";
import Overview from "./views/Overview";
import Inventory from "./views/Inventory";
import Wizards from "./views/Wizards";
import SamlTool from "./views/SamlTool";
import JwtTool from "./views/JwtTool";
import MetadataTool from "./views/MetadataTool";
import Playbooks from "./views/Playbooks";
import Learn from "./views/Learn";

const ROUTES = [
  { id: "overview", label: "Overview", group: "Manage", icon: Icon.overview, el: Overview },
  { id: "inventory", label: "Inventory", group: "Manage", icon: Icon.inventory, el: Inventory },
  { id: "wizards", label: "Setup wizards", group: "Manage", icon: Icon.wizards, el: Wizards },
  { id: "saml", label: "SAML decoder", group: "Troubleshoot", icon: Icon.saml, el: SamlTool },
  { id: "jwt", label: "JWT decoder", group: "Troubleshoot", icon: Icon.jwt, el: JwtTool },
  { id: "metadata", label: "Metadata checker", group: "Troubleshoot", icon: Icon.metadata, el: MetadataTool },
  { id: "playbooks", label: "Playbooks", group: "Troubleshoot", icon: Icon.playbooks, el: Playbooks },
  { id: "learn", label: "Learn", group: "Learn", icon: Icon.learn, el: Learn },
] as const;

const routeFromHash = () => {
  const h = location.hash.replace(/^#/, "");
  return ROUTES.some((r) => r.id === h) ? h : "overview";
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
  const groups = ["Manage", "Troubleshoot", "Learn"];

  return (
    <Ctx.Provider value={ctx}>
      <div className="shell">
        <nav className="rail" aria-label="Main">
          <div className="brand">
            <Mark />
            <div>
              <div className="brand-name">Federation 360</div>
              <div className="brand-sub">SAML · OIDC · OAuth</div>
            </div>
          </div>
          {groups.map((g) => (
            <div className="nav-group" key={g}>
              <div className="nav-label">{g}</div>
              {ROUTES.filter((r) => r.group === g).map((r) => (
                <a key={r.id} className="nav-item" href={"#" + r.id} aria-current={route === r.id ? "page" : undefined} onClick={() => setParams({})}>
                  {r.icon}
                  {r.label}
                </a>
              ))}
            </div>
          ))}
          <div className="rail-foot">
            <span>{store ? (store.kind === "cloud" ? "Inventory saved to this artifact" : "Inventory saved in this browser") : "Connecting storage…"}</span>
            <span>Tokens and assertions you paste stay on this page; nothing is sent anywhere.</span>
            <span>SCIM module: planned</span>
          </div>
        </nav>
        <main className="main">
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
