import { useState } from "react";
import { useApp, ProtoChip } from "../components/ui";
import { PLAYBOOKS, playbookById, type Playbook } from "../data/playbooks";
import type { ProtocolId } from "../lib/types";

const TOOL_LABEL: Record<string, string> = { saml: "SAML decoder", jwt: "JWT decoder", metadata: "Metadata checker", scim: "SCIM checker", inventory: "Inventory", wizards: "Setup wizards", discover: "Discover", grants: "OAuth grants", posture: "MFA and SSO coverage", detections: "Detections", flowtracer: "Flow tracer" };

function Detail({ p, onBack }: { p: Playbook; onBack: () => void }) {
  const { go } = useApp();
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <button className="btn ghost sm" onClick={onBack}>← All playbooks</button>
          <div className="row" style={{ marginBottom: 6 }}>
            {p.code && <span className="mono" style={{ fontWeight: 600 }}>{p.code}</span>}
            {p.protocols.map((x) => <ProtoChip key={x} p={x} />)}
            {p.platforms.map((x) => <span key={x} className="tag">{x}</span>)}
          </div>
          <h1>{p.title}</h1>
        </div>
        {p.code?.startsWith("AADSTS") && (
          <a className="btn" href={`https://login.microsoftonline.com/error?code=${p.code.replace("AADSTS", "")}`} target="_blank" rel="noreferrer">Microsoft's description ↗</a>
        )}
      </div>
      <section className="panel stack">
        <div className="eyebrow">What you see</div>
        <p>{p.symptom}</p>
        <div className="eyebrow" style={{ marginTop: 6 }}>What it means</div>
        <p style={{ maxWidth: "72ch" }}>{p.meaning}</p>
      </section>
      <div className="grid-3">
        <section className="panel stack">
          <h3>Likely causes</h3>
          <ul className="plain">{p.causes.map((c, i) => <li key={i}>{c}</li>)}</ul>
        </section>
        <section className="panel stack">
          <h3>How to confirm</h3>
          <ol className="actions">{p.checks.map((c, i) => <li key={i}>{c}</li>)}</ol>
        </section>
        <section className="panel stack">
          <h3>How to fix</h3>
          <ol className="actions">{p.fixes.map((c, i) => <li key={i}>{c}</li>)}</ol>
        </section>
      </div>
      {p.tools && (
        <div className="row">
          <span className="small muted">Open:</span>
          {p.tools.map((t) => <button key={t} className="btn sm" onClick={() => go(t)}>{TOOL_LABEL[t] ?? t}</button>)}
        </div>
      )}
    </div>
  );
}

export default function Playbooks() {
  const { params } = useApp();
  const [q, setQ] = useState("");
  const [proto, setProto] = useState<ProtocolId | "">((params.proto as ProtocolId) ?? "");
  const [open, setOpen] = useState<string>(params.id ?? "");
  const current = open ? playbookById(open) : undefined;
  if (current) return <Detail p={current} onBack={() => setOpen("")} />;

  const needle = q.trim().toLowerCase().replace(/^aadsts/, "");
  const list = PLAYBOOKS.filter(
    (p) =>
      (!proto || p.protocols.includes(proto)) &&
      (!needle || [p.code, p.title, p.symptom, p.meaning, ...(p.tags ?? []), ...p.platforms].join(" ").toLowerCase().includes(needle)),
  );
  const groups: { label: string; items: Playbook[] }[] = [
    { label: "Microsoft Entra ID errors (AADSTS)", items: list.filter((p) => p.code?.startsWith("AADSTS")) },
    { label: "SAML problems on the app side", items: list.filter((p) => !p.code && p.protocols.includes("saml") && !p.platforms.some((x) => x.startsWith("AWS")) && p.id !== "clock-skew" && p.id !== "groups-overage") },
    { label: "AWS", items: list.filter((p) => p.platforms.some((x) => x.startsWith("AWS"))) },
    { label: "Provisioning (SCIM)", items: list.filter((p) => p.id.startsWith("scim-")) },
    { label: "OAuth and OpenID Connect", items: list.filter((p) => !p.code && !p.protocols.includes("saml") && !p.id.startsWith("scim-")) },
    { label: "Any protocol", items: list.filter((p) => p.id === "clock-skew" || p.id === "groups-overage") },
  ];

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Playbooks</h1>
          <p>Search by error code (like 50011) or by what you see. Each playbook explains the error in plain words, lists the usual causes, how to confirm which one it is, and the fix.</p>
        </div>
      </div>
      <div className="row">
        <input aria-label="Search playbooks" className="input" style={{ maxWidth: 360 }} placeholder="Search: 50011, audience, expired, user not found…" value={q} onChange={(e) => setQ(e.target.value)} autoFocus />
        <select aria-label="Protocol" className="input" style={{ width: 180 }} value={proto} onChange={(e) => setProto(e.target.value as any)}>
          <option value="">All protocols</option>
          <option value="saml">SAML</option>
          <option value="oidc">OpenID Connect</option>
          <option value="oauth">OAuth</option>
          <option value="scim">SCIM</option>
        </select>
        <span className="small muted">{list.length} of {PLAYBOOKS.length}</span>
      </div>
      {list.length === 0 && (
        <div className="empty">
          <p>No playbook matches “{q}”.</p>
          {/^\d+$/.test(needle) && <a className="btn" href={`https://login.microsoftonline.com/error?code=${needle}`} target="_blank" rel="noreferrer">Look up AADSTS{needle} on Microsoft's error page ↗</a>}
        </div>
      )}
      {groups.filter((g) => g.items.length).map((g) => (
        <section key={g.label} className="stack">
          <h2>{g.label}</h2>
          <div className="table-wrap">
            <table>
              <tbody>
                {g.items.map((p) => (
                  <tr key={p.id} className="clickable" onClick={() => setOpen(p.id)}>
                    <td className="mono" style={{ width: 150, fontWeight: 600 }}>{p.code ?? ""}</td>
                    <td><strong>{p.title}</strong><div className="small muted">{p.symptom}</div></td>
                    <td style={{ whiteSpace: "nowrap" }}>{p.protocols.map((x) => <span key={x} style={{ marginRight: 4 }}><ProtoChip p={x} /></span>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  );
}
