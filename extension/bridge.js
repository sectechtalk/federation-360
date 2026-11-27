// Federation 360 Capture: passes captured sign-ins to the Federation 360 page it runs on, and the page's requests back.
// It runs only on Federation 360's own addresses and posts nothing into the page until the page itself asks, so no
// other page (another tool on localhost, for example) is ever handed a sign-in. Messages stay inside this tab.
(() => {
  // Kept in step with F360_ORIGINS and F360_SITE in capture-core.js and with manifest.json (tests check).
  const ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8080", "http://127.0.0.1:8080"];
  const SITE = "https://sectechtalk.github.io/federation-360/";
  if (!ORIGINS.includes(location.origin) && !location.href.startsWith(SITE)) return;

  const TAG = "f360-capture-extension";
  let asked = false;
  const toPage = (msg) => {
    if (asked && msg?.type === "flows") window.postMessage({ source: TAG, ...msg }, location.origin);
  };
  const ask = (type) => chrome.runtime.sendMessage({ type }).then(toPage, () => {});

  chrome.runtime.onMessage.addListener((msg) => toPage(msg));
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== location.origin || e.data?.source !== "f360-page") return;
    if (e.data.type !== "hello" && e.data.type !== "clear") return;
    asked = true;
    ask(e.data.type);
  });
})();
