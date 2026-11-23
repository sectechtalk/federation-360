// Federation 360 Capture: passes captured flows to the Federation 360 page it runs on, and the page's requests back.
// Runs only on Federation 360's own addresses (see manifest.json). Messages stay inside this tab.
(() => {
  const TAG = "f360-capture-extension";
  const toPage = (msg) => window.postMessage({ source: TAG, ...msg }, location.origin);
  const ask = (type) =>
    chrome.runtime.sendMessage({ type }).then(toPage, () => {});

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "flows") toPage(msg);
  });
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== location.origin || e.data?.source !== "f360-page") return;
    if (e.data.type === "hello" || e.data.type === "clear") ask(e.data.type);
  });
  ask("hello");
})();
