import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";

const port = 31068;
const server = spawn("npm", ["run", "start", "--", "-p", String(port)], {
  env: { ...process.env, NODE_ENV: "production", NEXT_TELEMETRY_DISABLED: "1" },
  stdio: ["ignore", "pipe", "pipe"],
  shell: process.platform === "win32",
});

let output = "";
server.stdout.on("data", (chunk) => { output += chunk; });
server.stderr.on("data", (chunk) => { output += chunk; });

async function waitForServer() {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/protected`);
      if (response.status === 401) return;
    } catch {
      // The production server has not started yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Next.js did not become ready: ${output}`);
}

try {
  await waitForServer();

  const normal = await fetch(`http://127.0.0.1:${port}/protected`);
  assert.equal(normal.status, 401, "a normal request must be rejected by middleware");

  const bypass = await fetch(`http://127.0.0.1:${port}/protected`, {
    headers: { "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware" },
  });
  assert.equal(bypass.status, 503, "the vulnerable request characteristic must reach the protected handler");
  assert.match(await bypass.text(), /challenge temporarily unavailable/, "the unavailable response must be fixed and non-secret");
} finally {
  server.kill();
  if (server.exitCode === null) await once(server, "exit");
}
