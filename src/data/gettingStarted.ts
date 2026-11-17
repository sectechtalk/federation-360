// Getting started: the first page Federation 360 opens on. Written for someone who has only heard of SAML, OIDC or SCIM and has
// just been told "you own this" at a new company. Plain words, no assumed knowledge, and every step points at a page
// Federation 360 already has. Overview shows today's health; this page is the path (first, next, ongoing). Keep them different.

export interface Basics {
  id: "saml" | "oidc" | "scim";
  name: string;
  short: string;
  oneLine: string;
  analogy: string;
  atWork: string;
}

export const BASICS: Basics[] = [
  {
    id: "saml",
    name: "SAML",
    short: "Single sign-on for (mostly older) business apps",
    oneLine:
      "Lets people use their one work account to sign in to another company's app, such as Salesforce, Workday or ServiceNow, without a separate password for each.",
    analogy:
      "Like showing your company badge at a partner's front desk. The partner doesn't check your password; they trust the badge your company printed.",
    atWork: "You'll hear: \"SSO\", \"the SAML cert is expiring\", \"entity ID\", \"reply URL\", \"the app says the assertion is invalid\".",
  },
  {
    id: "oidc",
    name: "OpenID Connect and OAuth",
    short: "Sign-in and permission for modern web, mobile and API apps",
    oneLine:
      "OpenID Connect (OIDC) does the same job as SAML for newer apps: it proves who the user is. OAuth, which OIDC is built on, decides what an app is allowed to do, such as read a calendar or call an API.",
    analogy:
      "OIDC is the ID card that says who you are. OAuth is a key card that opens only the rooms you were given, and expires after a while.",
    atWork: "You'll hear: \"app registration\", \"client ID\", \"client secret\", \"redirect URI\", \"token\", \"consent\", \"scopes\".",
  },
  {
    id: "scim",
    name: "SCIM",
    short: "Creating and removing user accounts in apps automatically",
    oneLine:
      "SCIM keeps an app's user list in step with your directory. When someone joins, their account appears in the app; when they leave, it is switched off, without anyone doing it by hand.",
    analogy:
      "Like HR sending every department the new-starter and leaver list, except it happens automatically within about 40 minutes.",
    atWork: "You'll hear: \"provisioning\", \"the user isn't in the app yet\", \"provisioning is in quarantine\", \"attribute mapping\", \"deprovisioning\".",
  },
];

export interface StartStep {
  id: string;
  phase: "first" | "next" | "ongoing";
  title: string;
  why: string;
  how: string;
  minutes: string;
  open: { label: string; route: string; params?: Record<string, string> };
}

export const PHASES: { id: StartStep["phase"]; title: string; sub: string }[] = [
  { id: "first", title: "Week 1: learn the words and get a safe place to practise", sub: "Nothing here touches your company's real systems." },
  { id: "next", title: "Weeks 2 to 3: find out what you actually own", sub: "Read-only. You look, you write it down, you change nothing." },
  { id: "ongoing", title: "Every week after that: keep it healthy", sub: "The routine that stops sign-in outages before users notice." },
];

export const START_STEPS: StartStep[] = [
  {
    id: "learn",
    phase: "first",
    title: "Learn what SAML, OIDC, OAuth and SCIM actually do",
    why: "Every page in Federation 360 uses a handful of words over and over. Twenty minutes on the Learn page makes the rest of Federation 360 readable.",
    how: "Read the four protocol cards and the one-sentence difference between sign-in and permission. Click through each flow under How the messages flow. Keep the Glossary at the bottom open when a word is new.",
    minutes: "20 min",
    open: { label: "Open Learn", route: "learn" },
  },
  {
    id: "lab",
    phase: "first",
    title: "Build your own free practice tenant",
    why: "You should never learn by experimenting on your company's live directory. A lab tenant is a free, private copy of Microsoft Entra ID that only you use, so nothing you break there matters.",
    how: "Follow Build your lab step by step. You create a free tenant and two accounts, then a script builds ready-made SAML, OIDC and SCIM test apps for you. It costs nothing as long as you add no Azure subscription or paid licences.",
    minutes: "60 min",
    open: { label: "Open Build your lab", route: "lab" },
  },
  {
    id: "lifecycle",
    phase: "first",
    title: "Practise one app's whole life: create, maintain, remove",
    why: "Almost everything you will be asked to do is one of three things: set up a new app, keep an existing one working, or switch one off. Doing all three once in the lab means none of them is new when it happens for real.",
    how: "On Learn, the Lifecycle section walks one example app (an expenses app) through all three stages for SAML, OIDC and SCIM. Every step says where to click and what success looks like.",
    minutes: "90 min",
    open: { label: "Open the lifecycle walkthrough", route: "learn" },
  },
  {
    id: "discover",
    phase: "next",
    title: "Read every app your company has connected",
    why: "Before you can own something you need a list of it. Most companies have far more SAML and OIDC apps than anyone remembers, and nobody has the full list.",
    how: "Practise on your lab tenant first. For your company's tenant, Discover needs a Global Administrator to approve read-only access once on Microsoft's consent screen, so ask your admin to sit with you for that first run. It reads every app, certificate, secret and owner and never changes anything.",
    minutes: "30 min",
    open: { label: "Open Discover", route: "discover" },
  },
  {
    id: "inventory",
    phase: "next",
    title: "Write down an owner and a contact for every app",
    why: "When an app breaks at 9 a.m. Monday you need to know who on the app side can help, and when its certificate expires you need someone to install the new one. Discover can't find that out; people can.",
    how: "In Inventory, open each app and fill in Owner and Notes. Start with the apps the most people use. Delete the fictional examples (marked Example) once your real apps are in.",
    minutes: "A few hours, spread out",
    open: { label: "Open Inventory", route: "inventory" },
  },
  {
    id: "overview",
    phase: "next",
    title: "Fix anything already broken or about to expire",
    why: "New owners often inherit a certificate that expires next month. Find it now, not when everyone's sign-in stops.",
    how: "Overview lists every app with a problem and every certificate or secret that expires in the next six months. Click one to see exactly what's wrong and which playbook fixes it.",
    minutes: "15 min",
    open: { label: "Open Overview", route: "overview" },
  },
  {
    id: "weekly",
    phase: "ongoing",
    title: "Check Overview once a week",
    why: "Expired certificates and secrets cause most SSO outages, and every one of them was visible weeks in advance.",
    how: "Look at Needs attention and Upcoming expirations. Anything under 30 days: contact the app's owner and plan the renewal. The Maintain stage on Learn shows how to roll a certificate without an outage.",
    minutes: "10 min a week",
    open: { label: "Open Overview", route: "overview" },
  },
  {
    id: "rescan",
    phase: "ongoing",
    title: "Re-read the tenant every month",
    why: "People add apps without telling you. A monthly Discover run catches new apps, new secrets and apps whose owner has left.",
    how: "Run Discover again. Its preview shows what is new or changed before anything is saved to Inventory.",
    minutes: "15 min a month",
    open: { label: "Open Discover", route: "discover" },
  },
  {
    id: "troubleshoot",
    phase: "ongoing",
    title: "Know where to go when someone says \"I can't sign in\"",
    why: "Sign-in errors look scary but almost all of them are one of about fifty known problems with a known fix.",
    how: "Search Playbooks for the error code on the user's screen (for example AADSTS50011). If there's no code, use Flow tracer to see every step of the sign-in and where it stopped.",
    minutes: "When it happens",
    open: { label: "Open Playbooks", route: "playbooks" },
  },
];

export interface Situation {
  when: string;
  do: string;
  open: { label: string; route: string; params?: Record<string, string> };
}

/** "Someone just asked me to..." router. Each points at the one page that answers it. */
export const SITUATIONS: Situation[] = [
  {
    when: "\"I can't sign in to an app\" and there's an error code",
    do: "Search the code in Playbooks. Each one says what it means, how to confirm the cause and the fix.",
    open: { label: "Open Playbooks", route: "playbooks" },
  },
  {
    when: "\"I can't sign in\" and there's no clear error",
    do: "Have the user record the sign-in in their browser and drop the file into Flow tracer. It shows each step and where it went wrong.",
    open: { label: "Open Flow tracer", route: "flowtracer" },
  },
  {
    when: "A new app needs single sign-on",
    do: "Use a setup wizard. It asks for the app's details, explains every field, and ends with a configuration sheet and a test plan.",
    open: { label: "Open Setup wizards", route: "wizards" },
  },
  {
    when: "\"New starters aren't showing up in the app\"",
    do: "That's SCIM provisioning. Copy the failed request from the Entra provisioning logs into SCIM checker. It explains what went wrong and points to the playbook that fixes it.",
    open: { label: "Open SCIM checker", route: "scim" },
  },
  {
    when: "A certificate or secret is about to expire",
    do: "Find it on Overview, then follow the Maintain stage on Learn to roll it over with the app's owner without an outage.",
    open: { label: "Open Overview", route: "overview" },
  },
  {
    when: "An app is being retired",
    do: "Follow the Remove stage on Learn: confirm nobody still uses it, disable sign-in first, then delete the app and close its record, in that order.",
    open: { label: "Open Learn", route: "learn" },
  },
  {
    when: "Security asks for a list of every app and when its credentials expire",
    do: "In Inventory, choose Export expiry report. It saves a file with names and expiry dates only, never the secrets themselves.",
    open: { label: "Open Inventory", route: "inventory" },
  },
  {
    when: "An app vendor sends you a metadata file or URL",
    do: "Paste it into Metadata checker to see the entity ID, sign-in URL and certificate dates before you type anything into Entra.",
    open: { label: "Open Metadata checker", route: "metadata" },
  },
];

/** Questions a new owner should get answered by their manager or the previous owner in week one. */
export const ASK_YOUR_TEAM: string[] = [
  "Which Microsoft Entra (or Okta) tenant is production, and are there test tenants too?",
  "Who owned this before me, and can I have 30 minutes with them?",
  "What access will I get: read-only to start, or admin? Who approves changes?",
  "Is there a change process (a ticket, a change window) before I touch a live app?",
  "Which apps matter most? If one broke, which would get the CEO's attention?",
  "Where do sign-in and access requests from users come in (help desk queue, email, chat)?",
  "Are there certificates or secrets anyone already knows are about to expire?",
];
