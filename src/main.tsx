import { startTheme } from "./360/theme";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";
import { consumeRedirect } from "./lib/discovery/entraLive";
import { acceptTestAppParam, consumeCaptureFragment, consumeLiveTestRedirect } from "./lib/livetest";
import { consumeLogsPopup, consumeSetupLink } from "./lib/entraLogs";

// Finish an Entra sign-in started on the Live test or Discover page before the app reads the address bar.
// Live test goes first and only takes sign-ins it started (matched by state); everything else is left for Discover.
// It also takes a capture handed back by the test app on Azure (#livetest&f360capture=…) and a ?testapp= link.
// The Flow tracer's sign-in log popup goes first: it closes itself and never renders the app.
if (!consumeLogsPopup()) {
  consumeLiveTestRedirect();
  consumeCaptureFragment();
  acceptTestAppParam();
  consumeRedirect();
  consumeSetupLink(); // #flowtracer&f360logs=… from signin-logs/Connect-F360SignInLogs.ps1
  startTheme();
  createRoot(document.getElementById("root")!).render(<App />);
}
