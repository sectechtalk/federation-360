import { useEffect, useState } from "react";
import { CodeBlock, useApp } from "../components/ui";
import { FlowView } from "../components/FlowView";
import { usePref } from "../lib/store";
import { KIND_LABEL, type FlowCapture } from "../lib/flow";
import { captureStore, DEFAULT_TESTAPP_URL, finishOidcTest, hasLiveTestResult, hasReturnedCapture, isAllowedTestAppUrl, startOidcTest, takeReturnedCapture, testApp, type CaptureSummary, type TestAppConfig } from "../lib/livetest";
import { browserSignInBlocker } from "../lib/discovery/entraLive";
import { WORKDIR } from "../data/workdir";

const START = `cd ${WORKDIR}
git pull
./lab/testapp/Start-F360TestApp.ps1`;

const DEPLOY_AZURE = `cd ${WORKDIR}
git pull
./lab/testapp/azure/Deploy-F360TestAppAzure.ps1 -TenantId <your lab tenant ID>`;

export default function LiveTest() {
  const { toast } = useApp();
  const [url, setUrl] = usePref("testAppUrl", DEFAULT_TESTAPP_URL);
  const [cfg, setCfg] = useState<TestAppConfig | null>(null);
  const [reachErr, setReachErr] = useState<string | null>(null);
  const [list, setList] = useState<CaptureSummary[]>([]);
  const [capture, setCapture] = useState<FlowCapture | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draftUrl, setDraftUrl] = useState(url);

  const mixed = location.protocol === "https:" && url.startsWith("http:");
  const app = testApp(url);
  // On your PC the test app keeps the captures; the Azure one keeps nothing, so this browser does.
  const captures = captureStore(url, cfg?.stateless);
  const onAzure = cfg?.host === "azure" || !!cfg?.stateless;

  const refresh = async () => {
    setReachErr(null);
    try {
      const c = await app.config();
      setCfg(c);
      setList(await captureStore(url, c.stateless).captures());
    } catch (e: any) {
      setCfg(null);
      setReachErr(e?.message ?? String(e));
    }
  };

  useEffect(() => {
    (async () => {
      // Back from Entra after the OIDC test.
      if (hasLiveTestResult()) {
        setBusy("Finishing the OpenID Connect sign-in…");
        try {
          const c = await finishOidcTest();
          if (c) setCapture(c);
        } catch (e: any) {
          setError(e?.message ?? String(e));
        }
        setBusy(null);
      }
      // Back from the test app on Azure after a SAML sign-in: the capture is in the URL fragment.
      if (hasReturnedCapture()) {
        try {
          const c = await takeReturnedCapture();
          if (c) setCapture(c);
        } catch (e: any) {
          setError(`Couldn't read the capture the test app sent back: ${e?.message ?? e}`);
        }
      }
      // Back from the test app on your PC after a SAML sign-in.
      const id = new URLSearchParams(location.search).get("capture");
      if (id) {
        history.replaceState(null, "", location.pathname + "#livetest");
        try {
          setCapture(await app.capture(id));
        } catch (e: any) {
          setError(`Couldn't load capture ${id}: ${e?.message ?? e}`);
        }
      }
      await refresh();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url]);

  useEffect(() => setDraftUrl(url), [url]);

  const useAddress = (u: string) => {
    const v = u.trim().replace(/\/+$/, "");
    if (!isAllowedTestAppUrl(v + "/")) {
      setError("Use http://localhost:5174 for the test app on your PC, or the https://….azurestaticapps.net address the Azure deploy script printed.");
      return;
    }
    setError(null);
    setCapture(null);
    setUrl(v);
  };

  const open = async (id: string) => {
    setError(null);
    try {
      setCapture(await captures.capture(id));
      window.scrollTo({ top: document.getElementById("live-result")?.offsetTop ?? 0, behavior: "smooth" });
    } catch (e: any) {
      setError(e?.message ?? String(e));
    }
  };

  const runCc = async () => {
    setBusy("Asking Entra for an app-only token…");
    setError(null);
    try {
      const c = await app.runClientCredentials();
      if (cfg?.stateless) await captures.save(c);
      setCapture(c);
      setList(await captures.captures());
    } catch (e: any) {
      setError(e?.message ?? String(e));
    }
    setBusy(null);
  };

  const runOidc = async () => {
    if (!cfg?.oidc || !cfg.tenantId) return;
    const blocked = browserSignInBlocker();
    if (blocked) {
      setError(blocked + " Open Federation 360 at http://localhost:5173/#livetest instead.");
      return;
    }
    setBusy("Sending you to Microsoft to sign in…");
    await startOidcTest({ tenantId: cfg.tenantId, ...cfg.oidc, loginHint: cfg.labUsers?.[0] }, url, !!cfg.stateless);
  };

  const clear = async () => {
    await captures.clear();
    setList([]);
    setCapture(null);
    toast(cfg?.stateless ? "All captures deleted from this browser" : "All captures deleted from the test app");
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Live test</h1>
          <p>Run real sign-ins against your lab tenant and see every hop. The lab test app (on your PC or on Azure's free tier) plays the app and the API; Entra, your test users and their tokens are real.</p>
        </div>
      </div>

      {mixed && (
        <div className="callout warn">
          This page is open over HTTPS, so the browser won't let it talk to the test app on http://localhost. Open your local Federation 360 instead: <span className="mono">http://localhost:5173/#livetest</span>
        </div>
      )}

      {!cfg && !mixed && (
        <section className="panel stack">
          <div className="panel-head"><h2>Start the test app</h2><span className="sub">{reachErr ? "Not reachable" : "Checking…"}</span></div>
          <p className="small" style={{ margin: 0 }}>
            The test app runs in Docker next to Federation 360, at <span className="mono">{url}</span>. If it isn't running yet, run this in PowerShell 7. It signs you in to the lab tenant, finds the lab apps, creates a certificate for the client credentials test, and starts the container.
          </p>
          <CodeBlock code={START} />
          <p className="small muted" style={{ margin: 0 }}>
            First time? The lab apps must exist first: merge the change, then run the lab workflow once (<span className="mono">./lab/Invoke-F360Lab.ps1 -Action apply</span>, or on GitHub: your repository &gt; Actions &gt; Lab tenant (Terraform) &gt; Run workflow, action <span className="mono">apply</span>).
          </p>
          <p className="small" style={{ margin: 0 }}>
            Or run it on Azure Static Web Apps (Free plan, $0) instead of Docker. This creates the site in your Azure subscription, copies the lab settings to it, and prints the address to use here:
          </p>
          <CodeBlock code={DEPLOY_AZURE} />
          <div className="row">
            <button className="btn primary" onClick={refresh}>Check again</button>
            <label className="field" style={{ minWidth: 260 }}>
              <span className="small muted">Test app address</span>
              <input className="input" value={draftUrl} onChange={(e) => setDraftUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && useAddress(draftUrl)} spellCheck={false} />
            </label>
            {draftUrl !== url && <button className="btn" onClick={() => useAddress(draftUrl)}>Use this address</button>}
            {url !== DEFAULT_TESTAPP_URL && <button className="btn" onClick={() => useAddress(DEFAULT_TESTAPP_URL)}>Use the one on this PC</button>}
          </div>
        </section>
      )}

      {cfg && !cfg.configured && (
        <div className="callout warn">The test app is running but has no lab settings. Run the PowerShell block below; it writes them and restarts the container.<CodeBlock code={START} /></div>
      )}

      {cfg?.configured && (
        <section className="panel stack">
          <div className="spread">
            <div>
              <div className="eyebrow">Lab tenant</div>
              <span className="mono small">{cfg.tenantId}</span>
            </div>
            <div>
              <div className="eyebrow">Test app</div>
              <span className="small">{onAzure ? "On Azure Static Web Apps (Free)" : "On this PC (Docker)"}</span> <span className="mono small muted">{url}</span>
            </div>
            <div className="row">
              {onAzure ? (
                <button className="btn sm" onClick={() => useAddress(DEFAULT_TESTAPP_URL)}>Use the one on this PC</button>
              ) : null}
              <button className="btn sm" onClick={refresh}>Refresh</button>
            </div>
          </div>
          {onAzure && <p className="small muted" style={{ margin: 0 }}>The Azure test app keeps nothing. Each run comes back to this page and is kept in this browser only (the last 30).</p>}
          <div className="callout">
            {cfg.labUsers?.length ? (
              <>When Microsoft asks, sign in as <strong className="mono">{cfg.labUsers[0]}</strong>{cfg.labUsers.length > 1 && <> (or {cfg.labUsers.slice(1).join(", ")})</>}. Use an InPrivate window if you're already signed in with another account. Lost the password? Reset it at entra.microsoft.com &gt; Users &gt; All users &gt; the user &gt; Reset password.</>
            ) : (
              <>Sign in with a lab test account: lab.user1@ followed by your lab tenant's onmicrosoft.com domain (not your own domain). Run the start script again to show the exact name here.</>
            )}
          </div>
          <div className="test-grid">
            <div className="panel stack">
              <div className="panel-head"><h2>SAML</h2><span className="sub">Test app as the service provider</span></div>
              <p className="small" style={{ margin: 0 }}>The test app sends a SAML request to Entra, you sign in as a lab user, and Entra posts a signed SAML response back to the test app.</p>
              {cfg.saml ? (
                <div className="stack">
                  <a className="btn primary" href={cfg.saml.loginUrl}>Run SAML sign-in</a>
                  <div className="row">
                    <a className="btn sm" href={`${cfg.saml.loginUrl}?fault=issuer`} title="Expect AADSTS700016">Break it: wrong Issuer</a>
                    <a className="btn sm" href={`${cfg.saml.loginUrl}?fault=acs`} title="Expect AADSTS50011">Break it: wrong reply URL</a>
                  </div>
                  <span className="small muted">The broken runs end on a Microsoft error page. Note the AADSTS code, come back here and open the capture to compare.</span>
                </div>
              ) : <span className="small muted">Not set up: LAB-TestApp-SAML wasn't found. Run the lab workflow, then the start script again.</span>}
            </div>

            <div className="panel stack">
              <div className="panel-head"><h2>OpenID Connect</h2><span className="sub">Federation 360 as the client</span></div>
              <p className="small" style={{ margin: 0 }}>Federation 360 signs you in with authorization code and PKCE, gets an ID token and an access token for LAB-API, and hands the access token to the test API to check.</p>
              {cfg.oidc ? <button className="btn primary" onClick={runOidc} disabled={!!busy}>Run OIDC sign-in</button> : <span className="small muted">Not set up: F360-LiveTest or LAB-API wasn't found.</span>}
            </div>

            <div className="panel stack">
              <div className="panel-head"><h2>Client credentials</h2><span className="sub">Test app as a daemon</span></div>
              <p className="small" style={{ margin: 0 }}>The test app signs in as LAB-Daemon with a certificate (no secret), gets an app-only token for LAB-API, and checks it like an API would.</p>
              {cfg.clientCredentials ? <button className="btn primary" onClick={runCc} disabled={!!busy}>Run client credentials</button> : <span className="small muted">{onAzure ? "Not set up: run the Azure deploy script again; it copies the certificate from your PC." : "Not set up: the start script creates the certificate."}</span>}
            </div>
          </div>
          {busy && <p className="small muted" style={{ margin: 0 }}>{busy}</p>}
        </section>
      )}

      {error && <div className="callout warn">{error}</div>}

      {list.length > 0 && (
        <section className="stack">
          <div className="spread">
            <h2>Recent runs</h2>
            <button className="btn sm danger" onClick={clear}>Delete all</button>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>When</th><th>Test</th><th>Hops</th><th /></tr></thead>
              <tbody>
                {list.map((c) => (
                  <tr key={c.id} aria-current={capture?.id === c.id ? "true" : undefined}>
                    <td className="small">{new Date(c.startedAt).toLocaleString()}</td>
                    <td><div>{c.title}</div><div className="small muted">{KIND_LABEL[c.kind]}</div></td>
                    <td className="small">{c.steps}</td>
                    <td><button className="btn sm" onClick={() => open(c.id)}>Open</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <div id="live-result">{capture && <FlowView capture={capture} />}</div>
    </div>
  );
}
