import { Fragment, useEffect, useState } from "react";
import { CodeBlock, FindingList, SummaryBar } from "./ui";
import { ActionButton, BusyNote, downloadFile } from "./busy";
import { ACTOR_LABEL, KIND_LABEL, analyzeCapture, redactCapture, type FlowAnalysis, type FlowCapture } from "../lib/flow";
import { CLAIM_HELP } from "../lib/jwt";
import { worst } from "../lib/health";

const time = (iso?: string) => (iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");

function prettyXml(xml: string) {
  let depth = 0;
  return xml
    .replace(/>\s*</g, "><")
    .replace(/></g, ">\n<")
    .split("\n")
    .map((line) => {
      if (/^<\//.test(line)) depth = Math.max(depth - 1, 0);
      const out = "  ".repeat(depth) + line;
      if (/^<[^!?/][^>]*[^/]>$/.test(line) && !/<\/[^>]+>$/.test(line)) depth++;
      return out;
    })
    .join("\n");
}

/** The timeline, decoded messages and findings for one sign-in flow. */
export function FlowView({ capture: latest }: { capture: FlowCapture }) {
  // The analysis and the capture it was made from. While a newer capture is being analyzed (a live sign-in that just
  // gained a hop) the previous one stays on screen, so the timeline never pairs hops with another capture's results.
  const [done, setDone] = useState<{ capture: FlowCapture; a: FlowAnalysis } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setErr(null);
    analyzeCapture(latest).then(
      (r) => live && setDone({ capture: latest, a: r }),
      (e) => live && setErr(String(e?.message ?? e)),
    );
    return () => {
      live = false;
    };
  }, [latest]);

  // A different flow (not a newer copy of the same one) shows "Analyzing…" instead of the old flow.
  const current = done && done.capture.id === latest.id ? done : null;
  const capture = current?.capture ?? latest;
  const a = current?.a ?? null;

  const download = async () => {
    const name = `f360-capture-${capture.id}.json`;
    const msg = downloadFile(name, JSON.stringify(await redactCapture(capture), null, 2), "application/json");
    return `${msg} Codes, token signatures and SAML signature values were removed.`;
  };

  if (err) return <div className="callout warn">Couldn't analyze this flow: {err}</div>;
  if (!a) return <BusyNote className="muted">Analyzing the sign-in…</BusyNote>;
  const all = [...a.overall, ...a.steps.flatMap((s) => s.findings)];

  return (
    <div className="stack">
      <section className="panel stack">
        <div className="spread">
          <div>
            <div className="eyebrow">{KIND_LABEL[capture.kind]} · {new Date(capture.startedAt).toLocaleString()} · {capture.steps.length} {capture.steps.length === 1 ? "hop" : "hops"}</div>
            <h2>{capture.title}</h2>
          </div>
          <div className="row">
            <SummaryBar findings={all} />
            <ActionButton className="btn sm" busy="Redacting…" onClick={download}>Download redacted copy</ActionButton>
          </div>
        </div>
        <FindingList findings={a.overall} />
      </section>

      <ol className="flow-steps">
        {capture.steps.map((s, i) => {
          const d = a.steps[i];
          const sev = worst(d.findings.filter((f) => f.severity !== "info"));
          return (
            <li key={i} className={`flow-step ${sev}`}>
              <div className="flow-num" aria-hidden="true">{i + 1}</div>
              <div className="stack" style={{ minWidth: 0 }}>
                <div className="spread">
                  <div>
                    <div className="eyebrow">{ACTOR_LABEL[s.from]} → {ACTOR_LABEL[s.to]}{s.at ? ` · ${time(s.at)}` : ""}</div>
                    <strong>{s.label}</strong>
                  </div>
                  {s.status ? <span className="tag">{s.method ? `${s.method} ` : ""}{s.status}</span> : s.method ? <span className="tag">{s.method}</span> : null}
                </div>
                {s.url && <div className="where">{s.url.length > 300 ? s.url.slice(0, 300) + "…" : s.url}</div>}
                {s.note && <p className="small muted" style={{ margin: 0 }}>{s.note}</p>}
                <FindingList findings={d.findings.filter((f) => f.severity !== "info" || f.playbook)} />
                {(s.params && Object.keys(s.params).length > 0) || d.saml || d.jwts.length || d.findings.some((f) => f.severity === "info") ? (
                  <details>
                    <summary>Details</summary>
                    <div className="stack" style={{ marginTop: 8 }}>
                      {s.params && Object.keys(s.params).length > 0 && (
                        <dl className="kv">
                          {Object.entries(s.params).map(([k, v]) => (
                            <Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>
                          ))}
                        </dl>
                      )}
                      {d.findings.some((f) => f.severity === "info" && !f.playbook) && <FindingList findings={d.findings.filter((f) => f.severity === "info" && !f.playbook)} />}
                      {d.saml && (
                        <>
                          <dl className="kv">
                            <dt>Message</dt><dd>{d.saml.parsed.kind} ({s.saml?.binding === "redirect" ? "Redirect binding" : "POST binding"})</dd>
                            <dt>ID</dt><dd>{d.saml.parsed.id || "—"}</dd>
                            <dt>Issuer</dt><dd>{d.saml.parsed.assertion?.issuer || d.saml.parsed.issuer || "—"}</dd>
                            {d.saml.parsed.request && <><dt>ACS URL</dt><dd>{d.saml.parsed.request.acsUrl || "—"}</dd></>}
                            {d.saml.parsed.assertion && (
                              <>
                                <dt>NameID</dt><dd>{d.saml.parsed.assertion.nameId || "—"}</dd>
                                <dt>Audience</dt><dd>{d.saml.parsed.assertion.audiences.join(", ") || "—"}</dd>
                                {d.saml.parsed.assertion.attributes.map((x) => (
                                  <Fragment key={x.name}><dt>{x.name.split("/").pop()}</dt><dd>{x.values.join(", ")}</dd></Fragment>
                                ))}
                              </>
                            )}
                          </dl>
                          <CodeBlock code={prettyXml(d.saml.xml)} />
                        </>
                      )}
                      {d.jwts.map(({ name, jwt }) => (
                        <div key={name} className="stack">
                          <span className="eyebrow">{name} claims</span>
                          <dl className="kv">
                            {Object.entries(jwt.payload).map(([k, v]) => (
                              <Fragment key={k}><dt title={CLAIM_HELP[k]}>{k}</dt><dd>{typeof v === "number" && ["exp", "nbf", "iat", "auth_time"].includes(k) ? `${v} (${new Date(v * 1000).toISOString().replace(".000", "")})` : typeof v === "string" ? v : JSON.stringify(v)}</dd></Fragment>
                            ))}
                          </dl>
                        </div>
                      ))}
                    </div>
                  </details>
                ) : null}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
