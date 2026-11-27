// Flow tracer training: a hands-on course for someone new to the team. Seven short exercises, each with a goal,
// click-by-click steps, what success looks like and what the exercise teaches. Shown on the Learn page.
//
// **Bold** marks the exact words of a button, heading or line on the screen. tests/flow-training.test.ts checks that
// every one of them still exists in the app, so the training can't drift from the screens.
// {domain} is replaced with the lab domain typed into the Learn page's "Your lab" boxes.
import { WORKDIR } from "./workdir";

export interface TrainingExercise {
  id: string;
  title: string;
  minutes: number;
  /** What you'll be able to do afterwards. */
  goal: string;
  /** What must be true before starting, if anything beyond the earlier exercises. */
  needs?: string;
  /** The page the exercise is done on. It opens in a new tab, so the steps stay in view. */
  open: { route: string; name: string };
  steps: string[];
  code?: { title: string; body: string };
  success: string;
  /** The point of the exercise, in one or two sentences. */
  learned: string;
}

/** Where the extension folder is, in a form the folder picker's address bar accepts. */
const EXTENSION_FOLDER = `${WORKDIR.replace("$HOME", "%USERPROFILE%")}\\extension`;

export const TRAINING_INTRO =
  "Flow tracer shows a sign-in the way the systems saw it: every hop between the app, the browser and the identity provider, each message decoded, and anything wrong flagged. This course takes about 45 minutes. Do the exercises in order; each one builds on the last. Exercises 1, 2, 3 and 7 need only this app and your browser. Exercises 4 and 5 use the practice lab. Exercise 6 needs a tenant with Entra ID P1 or higher.";

export const TRAINING_BEFORE = [
  "Federation 360 is open at http://localhost:5173 in Microsoft Edge or Google Chrome.",
  "Keep this page open for the steps. Each exercise has a button that opens the page you work on in a new tab.",
  "Every page starts with its sections folded. **Expand** opens one section, and **Expand all sections** at the top of a page opens them all.",
  "For exercises 4 and 5 you need the practice lab from **Build your lab** and the sign-in name of a lab user, written here as lab.user1@{domain}.",
];

export const TRAINING: TrainingExercise[] = [
  {
    id: "read-healthy",
    title: "Read a healthy sign-in",
    minutes: 5,
    goal: "Know what a working SAML sign-in looks like, so a broken one stands out.",
    open: { route: "flowtracer", name: "Flow tracer" },
    steps: [
      "Open Flow tracer in a new tab with the button above.",
      "On **Load a recording**, click **Expand**, then click **Healthy SAML sign-in**. This loads a built-in example; nothing leaves your browser. The page moves down to the result.",
      "Read the result's heading: SAML sign-in, 2 hops, and how many checks passed. Under it, the line **The flow completed** is marked Pass.",
      "Read hop 1, **The app sends a SAML request**. The line **ACS URL in request** is the address the app wants the answer sent to. Click **Details** to see the whole decoded request.",
      "Read hop 2, where the identity provider posts the SAML response to the app. Read its seven checks, from **Status: Success** down to **The response answers the request in this flow**.",
    ],
    success: "You see two hops, **The flow completed** marked Pass, and every check on both hops marked Pass.",
    learned: "A SAML sign-in is a request out and a signed response back, both carried by the browser. Flow tracer checks the response against the request, so you read results instead of XML.",
  },
  {
    id: "read-broken",
    title: "Read a broken sign-in and find the fix",
    minutes: 5,
    goal: "Go from an error to its cause and its fix without searching the web.",
    open: { route: "flowtracer", name: "Flow tracer" },
    steps: [
      "In the Flow tracer tab, click **Reply URL mismatch (AADSTS50011)**. It is in **Load a recording**, beside the first example.",
      "Read the result's heading. It now counts 2 problems, and the line **The flow has problems** tells you to look for the hops marked Problem.",
      "Find the hop marked Problem: **The identity provider shows an error page**. It names the code, AADSTS50011, and quotes Entra's own message.",
      "On hop 1, read **ACS URL in request**. The app sent https://expenses-old.contoso.example/saml/acs. In the healthy example it sent https://expenses.contoso.example/saml/acs. That difference is the whole problem.",
      "Click **Open the playbook →** on the Problem. On the playbook, click **Expand all sections** and read **The problem**, **Likely causes**, **How to confirm** and **How to fix**.",
      "Click **Flow tracer** in the left menu. The example is still open, so you can hold the fix against what the app sent.",
    ],
    success: "You can say in one sentence what AADSTS50011 means and what fixes it: the reply URL (SAML) or redirect URI (OpenID Connect) registered on the app in Entra must match what the app sends, character for character.",
    learned: "Start from the hop marked Problem, not from the top of the page. Every AADSTS code Flow tracer knows links to a playbook with the causes, how to confirm which one it is, and the fix.",
  },
  {
    id: "turn-on-capture",
    title: "Turn on automatic capture",
    minutes: 5,
    goal: "Make every sign-in in your browser appear in Flow tracer by itself.",
    open: { route: "flowtracer", name: "Flow tracer" },
    steps: [
      "In Microsoft Edge open edge://extensions in a new tab. In Google Chrome open chrome://extensions.",
      "Turn on **Developer mode**. It is on the left side in Edge and at the top right in Chrome.",
      `Click **Load unpacked** and choose the extension folder inside your Federation 360 folder. If you cloned it where the README says, paste ${EXTENSION_FOLDER} into the folder window's address bar.`,
      "For private windows, which exercise 4 uses: click **Details** on the Federation 360 Capture card, then turn on **Allow in InPrivate** (Edge) or **Allow in Incognito** (Chrome).",
      "Go back to the Flow tracer tab and press F5 to reload it.",
    ],
    success: "**Capturing** shows in green beside **Sign-ins in this browser**, and there is no yellow **Reload the capture extension** box.",
    learned: "Do this once per browser. The extension keeps only sign-in traffic, and from a form you post it keeps only the sign-in's own fields, never a typed password. It holds what it keeps in browser memory until the browser closes, hands it only to Federation 360's own pages, and sends nothing over the network. If the yellow box ever appears, the extension is older than this page expects: click **Reload** on its card (in Chrome it is the circular arrow), then reload Flow tracer.",
  },
  {
    id: "capture-live",
    title: "Capture a real sign-in",
    minutes: 10,
    needs: "Exercise 3 is done, including the private-window setting, and you have a lab user's password.",
    goal: "Watch a real sign-in arrive hop by hop and read it like the examples.",
    open: { route: "flowtracer", name: "Flow tracer" },
    steps: [
      "Keep the Flow tracer tab where you can see it. Two windows side by side work best.",
      "Press Ctrl+Shift+N to open an InPrivate window (Edge) or an Incognito window (Chrome), so a session you already have doesn't skip the sign-in.",
      "In that window go to https://myapps.microsoft.com and sign in as lab.user1@{domain}.",
      "Look at the Flow tracer tab. The count beside **Capturing** goes up and the newest sign-in opens by itself. An app can make more than one attempt, so there may be several: click **Expand** on **Sign-ins in this browser** to list them, newest first. Each one shows its time, its kind, the app it was for and, if it was stopped, the error code.",
      "Find a hop that starts **The app sends the user to sign in**. That is the authorize request. Click **Details** on it and find client_id (which app), redirect_uri (where the answer goes) and scope (what the app asked for).",
      "Find the hop where the identity provider sends the user back to the app with a code. If the app fetched its tokens inside the page, **The code is exchanged for tokens** follows it; click **Details** there to read the claims in each token.",
    ],
    success: "The sign-in is on the page without you saving, pasting or uploading anything, and you can point to the client ID, the redirect URI and the scopes.",
    learned: "You don't have to reproduce a problem twice. Sign in once and the evidence is already on the page. **Follow new sign-ins** keeps the newest one open; click an older one in the list to go back to it. Nothing arrived? The extension isn't allowed in private windows yet: redo step 4 of exercise 3.",
  },
  {
    id: "break-it",
    title: "Break a sign-in on purpose and diagnose it",
    minutes: 10,
    needs: "Exercise 3 is done, and the lab test app is running: **Live test** opens with a box that starts **Lab tenant**. If it shows **Start the test app** instead, expand that section and follow it first. If this browser is already signed in to Microsoft with another account, do this exercise in the private window from exercise 4: paste http://localhost:5173/#livetest into it.",
    goal: "Practice the whole troubleshooting loop on a failure you caused, where the right answer is known.",
    open: { route: "livetest", name: "Live test" },
    steps: [
      "Open Live test in a new tab with the button above and click **Expand all sections** at the top of the page. In the **SAML** box, click **Break it: wrong reply URL**. Sign in as lab.user1@{domain} if asked.",
      "Entra stops on an error page with a code that starts AADSTS. Don't fix anything. In that same tab, paste http://localhost:5173/#flowtracer into the address bar.",
      "The failed sign-in is the newest, so it is already open. Its heading names the app that asked for it: the test app, which is localhost:5174 when it runs on your PC. Find the hop marked Problem and read the code and Entra's message.",
      "On hop 1, read **ACS URL in request**: the reply URL the test app sent. Click **Open the playbook →**, then **Expand all sections**, and decide which of the **Likely causes** applies. Here you know the answer: the test app sent a reply URL that isn't registered.",
      "Paste http://localhost:5173/#livetest into the address bar, click **Expand all sections** and click **Break it: wrong Issuer**. Diagnose it from Flow tracer the same way, as if you hadn't seen the button's name. Each attempt is a sign-in of its own: **Expand** on **Sign-ins in this browser** lists both, each with its error code.",
      "Finish on **Live test** with **Run SAML sign-in**. This time Entra sends you back to Live test, and the run opens with **The flow completed**.",
    ],
    success: "You diagnosed two different failures from the captured sign-in alone, named the Entra setting behind each, and saw a clean sign-in afterwards.",
    learned: "The loop is always the same: capture, find the hop marked Problem, open the playbook, compare what the app sent with what Entra has registered, fix one thing, test again.",
  },
  {
    id: "entra-verdict",
    title: "Read Entra's verdict",
    minutes: 5,
    needs: "A tenant with Entra ID P1 or higher (Microsoft 365 E3, E5 and E7 include it) where an administrator has run the one-time setup below, and the Security Reader role on your account. The free practice lab can't do this exercise; read the last step instead.",
    goal: "See what Entra itself decided about a sign-in, including the Conditional Access policy that blocked it.",
    open: { route: "flowtracer", name: "Flow tracer" },
    code: {
      title: "One-time setup per tenant, run by a Global Administrator or Privileged Role Administrator in PowerShell 7. It adds a read-only app registration and grants it consent to read sign-in logs. It changes no sign-in settings. Ask before running it in a tenant you don't own.",
      body: `cd ${WORKDIR}\n./signin-logs/Connect-F360SignInLogs.ps1 -TenantId <tenant ID or domain>`,
    },
    steps: [
      "Sign in to any app in that tenant in another tab, so Flow tracer captures it.",
      "In the Flow tracer tab, find the box headed **Entra's verdict** above the hops and click **Expand** on it.",
      "Click **Sign in to read sign-in logs** and pick your account in the window that opens. One sign-in lasts 24 hours. If the box shows setup steps instead of that button, the one-time setup hasn't been run for this tenant yet.",
      "Wait. Entra writes a sign-in to its log 2 to 5 minutes after it happens, and the box keeps checking by itself.",
      "Read the verdict: who signed in to what, whether Entra allowed it, which Conditional Access policies applied, and **What to do** if it failed. Open **Sign-in log details** for the raw entry: request ID, correlation ID, IP address and client.",
      "On a free tenant the box says the license doesn't allow it, and tells you where the same entry is in the Entra admin center: Entra ID > Monitoring & health > Sign-in logs.",
    ],
    success: "The box says whether Entra let the user in. For a failed sign-in it names the error, the policy and the fix.",
    learned: "The hops show what the browser saw. The verdict shows what Entra decided and why. Together they answer both halves of “why can't this user get in?”. Tokens that an app's own server requests never pass through the browser, so for those sign-ins the verdict is the only evidence.",
  },
  {
    id: "share-safely",
    title: "Share what you found, safely",
    minutes: 5,
    goal: "Hand a sign-in to a colleague or a vendor without handing over live credentials.",
    open: { route: "flowtracer", name: "Flow tracer" },
    steps: [
      "In the Flow tracer tab, open any sign-in. An example from exercise 1 or 2 works.",
      "Click **Download redacted copy**, beside the result's heading. The file keeps the hops and removes codes, token signatures and SAML signature values.",
      "Check the file: on **Load a recording**, drop it on the dashed box, or click the box and choose it. It opens with the same hops.",
      "When a troubleshooting session is over and the extension is on, click **Expand** on **Sign-ins in this browser**, then **Clear list**.",
    ],
    success: "You have a file you can attach to a ticket, and it opens in Flow tracer on someone else's computer.",
    learned: "A raw browser recording (a HAR file, short for HTTP Archive) holds live session cookies and tokens. Treat it like a password. Never email one or attach it to a ticket; share the redacted copy.",
  },
];

/** Questions to answer out loud at the end. If you can't, redo the exercise named. */
export const TRAINING_CHECK: { q: string; a: string; exercise: string }[] = [
  { q: "A user gets AADSTS50011. Which two things do you compare?", a: "The reply URL or redirect URI the app sent (ACS URL in request, or redirect_uri in the authorize request's Details) and the ones registered on the app in Entra.", exercise: "read-broken" },
  { q: "Where in a captured OpenID Connect sign-in do you find which app it was?", a: "client_id, in the Details of the authorize request.", exercise: "capture-live" },
  { q: "The hops look fine but the user is still blocked. Where do you look next?", a: "Entra's verdict. It names the Conditional Access policy or the error Entra recorded.", exercise: "entra-verdict" },
  { q: "A vendor asks for a recording of the failed sign-in. What do you send?", a: "The file from Download redacted copy, never the raw HAR file.", exercise: "share-safely" },
  { q: "Flow tracer shows no token for a web app's sign-in. Is something broken?", a: "No. The app's server fetched the token straight from the identity provider, which never passes through the browser. Use Entra's verdict.", exercise: "entra-verdict" },
  { q: "Does the capture extension keep the password you type on a sign-in page?", a: "No. From a posted form it keeps only the sign-in's own fields. It does keep the codes and tokens a sign-in brings back, so treat the browser like any place that holds live tokens.", exercise: "turn-on-capture" },
];
