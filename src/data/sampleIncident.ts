// A made-up incident for Investigate: the Detections sample log plus Exchange evidence for Blair, whose account was
// pushed with MFA prompts: a phishing mail first, then a forwarding rule after the takeover. Fictional domain and
// documentation-range addresses (RFC 5737) only.
import { sampleSignInLog } from "../detections/sample";

const D = "f360sample.onmicrosoft.com";
const MIN = 60_000;

export function sampleIncidentFiles(now = new Date()): { name: string; text: string }[] {
  const log = sampleSignInLog(now);
  const base = now.getTime() - 20 * 60 * MIN; // the same start as the sample log
  const t = (m: number) => new Date(base + m * MIN).toISOString();
  const trace = [
    { Received: t(290), SenderAddress: "it-support@northwind-helpdesk.example", RecipientAddress: `blair.ops@${D}`, Subject: "Action required: confirm your MFA device", Status: "Delivered", FromIP: "203.0.113.200" },
    { Received: t(120), SenderAddress: `jo.people@${D}`, RecipientAddress: `blair.ops@${D}`, Subject: "Team lunch Friday", Status: "Delivered", FromIP: "" },
  ];
  const rules = [
    { Name: "..", Enabled: true, MailboxOwnerId: `blair.ops@${D}`, ForwardTo: ["\"collector\" [SMTP:collector@mail-drop.example]"], DeleteMessage: false, MoveToFolder: "RSS Feeds", SubjectContainsWords: ["invoice", "payment", "wire"], Description: "If the subject includes invoice, payment or wire, forward to collector@mail-drop.example and move to RSS Feeds" },
    { Name: "Newsletters", Enabled: true, MailboxOwnerId: `blair.ops@${D}`, ForwardTo: null, DeleteMessage: false, MoveToFolder: "Newsletters", From: ["news@contoso.example"] },
  ];
  return [
    { name: "sample-signins-and-audits.json", text: JSON.stringify(log, null, 2) },
    { name: "sample-message-trace-blair.json", text: JSON.stringify(trace, null, 2) },
    { name: "sample-inbox-rules-blair.json", text: JSON.stringify(rules, null, 2) },
  ];
}
