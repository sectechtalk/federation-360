// Federation 360 Capture: on a Microsoft sign-in page, reports an AADSTS error shown on the page, so Flow tracer can
// explain it. Browsers don't let extensions read page responses from the network, so it reads the visible page text.
(() => {
  let sent = false;
  const look = () => {
    if (sent || !document.body) return;
    const m = document.body.innerText.match(/AADSTS\d{4,}[^\n]{0,300}/);
    if (!m) return;
    sent = true;
    // The "Troubleshooting details" box (often collapsed) holds the IDs Entra's sign-in log is keyed by.
    const all = document.body.textContent || "";
    const id = (label) => all.match(new RegExp(label + "\\s*:?\\s*([0-9a-f]{8}-[0-9a-f-]{27})", "i"))?.[1];
    chrome.runtime.sendMessage({ type: "idp-error", url: location.href, text: m[0], requestId: id("Request Id"), correlationId: id("Correlation Id") }).catch(() => {});
  };
  look();
  const obs = new MutationObserver(look);
  obs.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  setTimeout(() => obs.disconnect(), 15000);
})();
