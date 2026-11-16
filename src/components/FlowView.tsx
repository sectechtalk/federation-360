import { Fragment, useEffect, useState } from "react";
import { CodeBlock, FindingList, SummaryBar, useApp } from "./ui";
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

export function downloadJson(name: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** The timeline, decoded messages and findings for one sign-in flow. */
export function FlowView({ capture }: { capture: FlowCapture }) {
  const { toast } = useApp();
  const [a, setA] = useState<FlowAnalysis | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setA(null);
    analyzeCapture(capture).then(
      (r) => live && setA(r),
      (e) => live && setErr(String(e?.message ?? e)),
    );
    return () => {
      live = false;
    };
  }, [capture]);

  const download = async () => {
    downloadJson(`f360-capture-${capture.id}.json`, await redactCapture(capture));
    toast("Saved with codes, token signatures and SAML signature values removed");
  };

  if (err) return <div className="callout warn">Couldn't analyze this flow: {err}</div>;
  if (!a) return <p className="muted">Analyzing…</p>;
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
            <button className="btn sm" onClick={download}>Download redacted copy</button>
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
