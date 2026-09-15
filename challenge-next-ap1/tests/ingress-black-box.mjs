import assert from "node:assert/strict";

const baseUrl = process.env.AP1_BASE_URL;
if (!baseUrl) throw new Error("AP1_BASE_URL is required");

let normal;
for (let attempt = 0; attempt < 40; attempt += 1) {
  try {
    normal = await fetch(`${baseUrl}/ap1/protected`);
    if (normal.status === 401) break;
  } catch {
    // The isolated ingress has not started yet.
  }
  await new Promise((resolve) => setTimeout(resolve, 250));
}
assert.ok(normal, "the AP-01 ingress must become available");
assert.equal(normal.status, 401, "normal AP-01 requests must be rejected");

const bypass = await fetch(`${baseUrl}/ap1/protected`, {
  headers: { "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware" },
});
assert.equal(bypass.status, 200, "the AP-01 bypass request must reach the consumer");
const response = await bypass.text();
assert.match(response, /K3DF\{[A-Za-z0-9_-]{43}\}/, "the consumer response must remain in memory");
