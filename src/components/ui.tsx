import { createContext, useContext, useState, type ReactNode } from "react";
import type { AppIntegration, Finding, ProtocolId, Severity, Tenant } from "../lib/types";
import type { Store } from "../lib/store";
import { protocolById } from "../lib/protocols";
import type { Flow } from "../data/learn";

export interface AppCtx {
  store: Store | null;
  tenants: Tenant[];
  apps: AppIntegration[];
  loading: boolean;
  go: (route: string, params?: Record<string, string>) => void;
  params: Record<string, string>;
  toast: (msg: string) => void;
  loadExamples: () => Promise<void>;
}
export const Ctx = createContext<AppCtx>(null as any);
export const useApp = () => useContext(Ctx);

export function ProtoChip({ p }: { p: ProtocolId }) {
  return <span className={`chip proto-${p}`}>{protocolById(p).short}</span>;
}

const SEV_LABEL: Record<Severity, string> = { ok: "Pass", info: "Note", warn: "Warning", critical: "Problem" };
export function Sev({ s, label }: { s: Severity; label?: string }) {
  return (
    <span className={`sev sev-${s}`}>
      <span className="dot" />
      {label ?? SEV_LABEL[s]}
    </span>
  );
}

export function FindingList({ findings }: { findings: Finding[] }) {
  const { go } = useApp();
  const order: Severity[] = ["critical", "warn", "info", "ok"];
  const sorted = [...findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  if (!findings.length) return null;
  return (
    <div className="findings">
      {sorted.map((f, i) => (
        <div className={`finding ${f.severity}`} key={i}>
          <div className="stripe" />
          <div className="body">
            <div className="title">
              <Sev s={f.severity} />
              <span>{f.title}</span>
            </div>
            {f.detail && <div className="detail">{f.detail}</div>}
            {f.playbook && (
              <div>
                <button className="btn sm ghost" onClick={() => go("playbooks", { id: f.playbook! })}>
                  Open the playbook →
                </button>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

export function SummaryBar({ findings }: { findings: Finding[] }) {
  const c = (s: Severity) => findings.filter((f) => f.severity === s).length;
  return (
    <div className="summary-bar">
      {c("critical") > 0 && <Sev s="critical" label={`${c("critical")} problem${c("critical") > 1 ? "s" : ""}`} />}
      {c("warn") > 0 && <Sev s="warn" label={`${c("warn")} warning${c("warn") > 1 ? "s" : ""}`} />}
      {c("ok") > 0 && <Sev s="ok" label={`${c("ok")} passed`} />}
      {c("info") > 0 && <Sev s="info" label={`${c("info")} notes`} />}
    </div>
  );
}

export function copyText(text: string, toast: (m: string) => void) {
  navigator.clipboard?.writeText(text).then(
    () => toast("Copied"),
    () => toast("Copy isn't allowed here. Select the text and copy it manually."),
  );
}

export function CodeBlock({ code, wrap }: { code: string; wrap?: boolean }) {
  const { toast } = useApp();
  return (
    <div className="code-block">
      <pre className={`code${wrap ? " wrap" : ""}`}>{code}</pre>
      <button className="btn sm copy" onClick={() => copyText(code, toast)}>
        Copy
      </button>
    </div>
  );
}

export function Field(props: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  hint?: ReactNode;
  error?: string | null;
  multiline?: boolean;
  rows?: number;
  type?: string;
  options?: string[];
}) {
  const { id, label, value, onChange, placeholder, hint, error, multiline, rows, type, options } = props;
  return (
    <label className="field" htmlFor={id}>
      <span>{label}</span>
      {options ? (
        <select id={id} className="input" value={value} onChange={(e) => onChange(e.target.value)}>
          {options.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      ) : multiline ? (
        <textarea id={id} className="input" rows={rows ?? 3} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} spellCheck={false} />
      ) : (
        <input id={id} className="input" type={type ?? "text"} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} spellCheck={false} />
      )}
      {error ? <span className="err">{error}</span> : hint ? <span className="hint">{hint}</span> : null}
    </label>
  );
}

export function Seg<T extends string>({ value, options, onChange, label }: { value: T; options: { v: T; l: string }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.v} aria-pressed={value === o.v} onClick={() => onChange(o.v)} type="button">
          {o.l}
        </button>
      ))}
    </div>
  );
}

/** App picker used by the decoders to compare against the inventory. */
export function AppPicker({ value, onChange, protocols, id }: { value: string; onChange: (v: string) => void; protocols: ProtocolId[]; id: string }) {
  const { apps, tenants } = useApp();
  const list = apps.filter((a) => protocols.includes(a.protocol));
  return (
    <label className="field" htmlFor={id}>
      <span>Compare with an app in your inventory</span>
      <select id={id} className="input" value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Don't compare (just decode)</option>
        {list.map((a) => (
          <option key={a.id} value={a.id}>
            {a.name} · {tenants.find((t) => t.id === a.tenantId)?.name ?? "no tenant"} · {a.environment}
          </option>
        ))}
      </select>
    </label>
  );
}

export function useToastState() {
  const [msg, setMsg] = useState<string | null>(null);
  const toast = (m: string) => {
    setMsg(m);
    window.clearTimeout((toast as any)._t);
    (toast as any)._t = window.setTimeout(() => setMsg(null), 2400);
  };
  return { msg, toast };
}

export function SequenceDiagram({ flow }: { flow: Flow }) {
  const colW = 220;
  const left = 30;
  const width = left * 2 + colW * (flow.actors.length - 1) + 160;
  const x = (i: number) => left + 80 + i * colW;
  const rowH = 46;
  const top = 50;
  const height = top + flow.steps.length * rowH + 20;
  return (
    <div className="seq-wrap">
      <svg className="seq" viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="img" aria-label={flow.title}>
        {flow.actors.map((a, i) => (
          <g key={a}>
            <rect className="actor-box" x={x(i) - 75} y={6} width={150} height={30} rx={6} />
            <text x={x(i)} y={26} textAnchor="middle" fontSize={12.5} fontWeight={600}>
              {a}
            </text>
            <line className="life" x1={x(i)} y1={36} x2={x(i)} y2={height - 8} />
          </g>
        ))}
        {flow.steps.map((s, i) => {
          const y = top + i * rowH + 14;
          if (s.from === s.to) {
            const cx = x(s.from);
            return (
              <g key={i}>
                <path className="arrow" d={`M${cx} ${y - 6} h26 v14 h-22`} />
                <polygon className="head" points={`${cx + 2},${y + 8} ${cx + 9},${y + 4} ${cx + 9},${y + 12}`} />
                <text className="label" x={cx + 34} y={y + 2}>
                  {i + 1}. {s.label}
                </text>
                {s.note && (
                  <text className="note" x={cx + 34} y={y + 17}>
                    {s.note}
                  </text>
                )}
              </g>
            );
          }
          const x1 = x(s.from);
          const x2 = x(s.to);
          const dir = x2 > x1 ? 1 : -1;
          const mid = (x1 + x2) / 2;
          return (
            <g key={i}>
              <line className="arrow" x1={x1} y1={y} x2={x2 - dir * 6} y2={y} />
              <polygon className="head" points={`${x2},${y} ${x2 - dir * 8},${y - 4} ${x2 - dir * 8},${y + 4}`} />
              <text className="label" x={mid} y={y - 6} textAnchor="middle">
                {i + 1}. {s.label}
              </text>
              {s.note && (
                <text className="note" x={mid} y={y + 15} textAnchor="middle">
                  {s.note}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export const Icon = {
  overview: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></svg>,
  inventory: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M4 6h16M4 12h16M4 18h10" /></svg>,
  wizards: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M5 19 19 5M14 5h5v5" /><circle cx="6" cy="6" r="1.5" /><circle cx="18" cy="18" r="1.5" /></svg>,
  saml: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="m8 7-5 5 5 5M16 7l5 5-5 5" /></svg>,
  jwt: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="8" cy="12" r="4" /><path d="M12 12h9M18 12v3M21 12v2" /></svg>,
  scim: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="8" cy="8" r="3.2" /><path d="M2.5 19c.6-3.2 2.8-5 5.5-5s4.9 1.8 5.5 5" /><path d="M15 8h6m-2.5-2.5L21 8l-2.500 2.500M21 15h-6m2.500-2.500L15 15l2.500 2.500" /></svg>,
  metadata: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3 4 7v5c0 5 3.5 8 8 9 4.5-1 8-4 8-9V7z" /><path d="m9 12 2 2 4-4" /></svg>,
  playbooks: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z" /><path d="M5 17a3 3 0 0 1 3-3h11" /></svg>,
  lab: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4a2 2 0 0 0 1.8-3l-5-9V3" /><path d="M7.5 15h9" /></svg>,
  discover: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="6.5" /><path d="m20 20-4.2-4.2M8.5 11h5M11 8.5v5" /></svg>,
  learn: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="m2 9 10-5 10 5-10 5z" /><path d="M6 11v5c3 2 9 2 12 0v-5" /></svg>,
};
