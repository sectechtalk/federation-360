import { useEffect, useState } from "react";
import { CodeBlock, useApp } from "../components/ui";
import { ActionButton, BusyNote, LeaveLink, Spinner } from "../components/busy";
import { FlowView } from "../components/FlowView";
import { usePref } from "../lib/store";
import { KIND_LABEL, type FlowCapture } from "../lib/flow";
import { captureStore, DEFAULT_TESTAPP_URL, finishOidcTest, hasLiveTestResult, hasReturnedCapture, isAllowedTestAppUrl, startOidcTest, takeReturnedCapture, testApp, type CaptureSummary, type TestAppConfig } from "../lib/livetest";
import { browserSignInBlocker } from "../lib/discovery/entraLive";
import { WORKDIR } from "../data/workdir";
import { Section, openSection } from "../components/Section";

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

  /** Reads the test app's settings and runs. Returns the error text, or null when the test app answered. */
  const refresh = async (): Promise<string | null> => {
    setReachErr(null);
    try {
      const c = await app.config();
      setCfg(c);
      setList(await captureStore(url, c.stateless).captures());
      return null;
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      setCfg(null);
      setReachErr(msg);
      return msg;
    }
  };
  const checkNow = async () => {
    const err = await refresh();
    if (err) throw new Error(`The test app at ${url} didn't answer: ${err}`);
    return `The test app at ${url} answered`;
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
  // A capture you opened or just ran shows its summary section open, and the page scrolls to it.
  useEffect(() => {
    if (capture) openSection("flow-summary", true);
  }, [capture]);

  const useAddress = (u: string) => {
    const v = u.trim().replace(/\/+$/, "");
    if (!isAllowedTestAppUrl(v + "/")) {
      setError("Use http://localhost:5174 for the test app on your PC, or the https://….azurestaticapps.net address the Azure deploy script printed.");
      return;
    }
    setError(null);
    setCapture(null);
    setUrl(v);
    toast(`Switched to ${v}. Checking it now…`);
  };

  const open = async (id: string) => {
    setError(null);
    setCapture(await captures.capture(id));
    return "Opened below";
  };

  const runCc = async () => {
    setError(null);
    const c = await app.runClientCredentials();
    if (cfg?.stateless) await captures.save(c);
    setCapture(c);
    setList(await captures.captures());
    return "Token received and checked. The result is below.";
  };

  const runOidc = async () => {
    if (!cfg?.oidc || !cfg.tenantId) throw new Error("The test app has no OpenID Connect settings.");
    const blocked = browserSignInBlocker();
    if (blocked) throw new Error(blocked + " Open Federation 360 at http://localhost:5173/#livetest instead.");
    await startOidcTest({ tenantId: cfg.tenantId, ...cfg.oidc, loginHint: cfg.labUsers?.[0] }, url, !!cfg.stateless);
    // The browser normally leaves for Microsoft's sign-in page before this wait ends.
    await new Promise((r) => setTimeout(r, 15000));
    throw new Error("Microsoft's sign-in page didn't open. Select Run OIDC sign-in again.");
  };

  const clear = async () => {
    await captures.clear();
    setList([]);
    setCapture(null);
    const msg = cfg?.stateless ? "All captures deleted from this browser" : "All captures deleted from the test app";
    toast(msg);
    return msg;
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
        <Section className="panel stack">
          <div className="panel-head"><h2>Start the test app</h2><span className="sub">{reachErr ? "Not reachable" : <span className="row" role="status"><Spinner /> Checking…</span>}</span></div>
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
            <ActionButton className="btn primary" busy="Checking…" onClick={checkNow}>Check again</ActionButton>
            <label className="field" style={{ minWidth: 260 }}>
              <span className="small muted">Test app address</span>
              <input className="input" value={draftUrl} onChange={(e) => setDraftUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && useAddress(draftUrl)} spellCheck={false} />
            </label>
            {draftUrl !== url && <button className="btn" onClick={() => useAddress(draftUrl)}>Use this address</button>}
            {url !== DEFAULT_TESTAPP_URL && <button className="btn" onClick={() => useAddress(DEFAULT_TESTAPP_URL)}>Use the one on this PC</button>}
          </div>
        </Section>
      )}

      {cfg && !cfg.configured && (
        <div className="callout warn">The test app is running but has no lab settings. Run the PowerShell block below; it writes them and restarts the container.<CodeBlock code={START} /></div>
      )}

      {cfg?.configured && (
        <Section className="panel stack">
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
              <ActionButton className="btn sm" busy="Checking…" onClick={checkNow}>Refresh</ActionButton>
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
            <Section className="panel stack">
              <div className="panel-head"><h2>SAML</h2><span className="sub">Test app as the service provider</span></div>
              <p className="small" style={{ margin: 0 }}>The test app sends a SAML request to Entra, you sign in as a lab user, and Entra posts a signed SAML response back to the test app.</p>
              {cfg.saml ? (
                <div className="stack">
                  <LeaveLink className="btn primary" href={cfg.saml.loginUrl}>Run SAML sign-in</LeaveLink>
                  <div className="row">
                    <LeaveLink className="btn sm" href={`${cfg.saml.loginUrl}?fault=issuer`} title="Expect AADSTS700016">Break it: wrong Issuer</LeaveLink>
                    <LeaveLink className="btn sm" href={`${cfg.saml.loginUrl}?fault=acs`} title="Expect AADSTS50011">Break it: wrong reply URL</LeaveLink>
                  </div>
                  <span className="small muted">The broken runs end on a Microsoft error page. Note the AADSTS code, come back here and open the capture to compare.</span>
                </div>
              ) : <span className="small muted">Not set up: LAB-TestApp-SAML wasn't found. Run the lab workflow, then the start script again.</span>}
            </Section>

            <Section className="panel stack">
              <div className="panel-head"><h2>OpenID Connect</h2><span className="sub">Federation 360 as the client</span></div>
              <p className="small" style={{ margin: 0 }}>Federation 360 signs you in with authorization code and PKCE, gets an ID token and an access token for LAB-API, and hands the access token to the test API to check.</p>
              {cfg.oidc ? <ActionButton className="btn primary" busy="Opening Microsoft sign-in…" onClick={runOidc} disabled={!!busy}>Run OIDC sign-in</ActionButton> : <span className="small muted">Not set up: F360-LiveTest or LAB-API wasn't found.</span>}
            </Section>

            <Section className="panel stack">
              <div className="panel-head"><h2>Client credentials</h2><span className="sub">Test app as a daemon</span></div>
              <p className="small" style={{ margin: 0 }}>The test app signs in as LAB-Daemon with a certificate (no secret), gets an app-only token for LAB-API, and checks it like an API would.</p>
              {cfg.clientCredentials ? <ActionButton className="btn primary" busy="Asking Entra for a token…" onClick={runCc} disabled={!!busy}>Run client credentials</ActionButton> : <span className="small muted">{onAzure ? "Not set up: run the Azure deploy script again; it copies the certificate from your PC." : "Not set up: the start script creates the certificate."}</span>}
            </Section>
          </div>
          {busy && <BusyNote className="small muted">{busy}</BusyNote>}
        </Section>
      )}

      {error && <div className="callout warn">{error}</div>}

      {list.length > 0 && (
        <Section className="stack">
          <div className="spread">
            <h2>Recent runs</h2>
            <ActionButton className="btn sm danger" busy="Deleting…" onClick={clear}>Delete all</ActionButton>
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
                    <td><ActionButton className="btn sm" busy="Opening…" report="toast" quietOk onClick={() => open(c.id)}>Open</ActionButton></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      <div id="live-result">{capture && <FlowView capture={capture} />}</div>
    </div>
  );
}
