import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// F360_POLL=1 (set by docker-compose.yml) makes the dev server poll for file changes,
// which hot reload needs when the source is bind-mounted from Windows into a container.
const poll = process.env.F360_POLL === "1";

export default defineConfig({
  plugins: [react(), viteSingleFile()],
  server: poll ? { watch: { usePolling: true, interval: 300 } } : {},
  test: { environment: "jsdom", globals: true },
} as any);
