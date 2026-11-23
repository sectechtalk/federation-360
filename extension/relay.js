// Federation 360 Capture: passes what token-hook.js saw in this page to the extension. Only token responses from a
// known identity provider are accepted (background.js checks again).
window.addEventListener("message", (e) => {
  if (e.source !== window || e.data?.source !== "f360-capture-page-hook" || e.data.type !== "token-response") return;
  const { url, request, status, body } = e.data;
  if (typeof url !== "string" || typeof body !== "string") return;
  chrome.runtime.sendMessage({ type: "token-response", url, request: String(request ?? ""), status: Number(status) || 0, body }).catch(() => {});
});
