const baseUrl = process.env.AP1_BASE_URL;

if (!baseUrl) {
  throw new Error("AP1_BASE_URL is required");
}

const protectedUrl = new URL("/protected", baseUrl);

const normalResponse = await fetch(protectedUrl);
if (normalResponse.status !== 401) {
  throw new Error(`normal request expected 401, received ${normalResponse.status}`);
}

const bypassResponse = await fetch(protectedUrl, {
  headers: { "x-middleware-subrequest": "middleware" },
});
const bypassBody = await bypassResponse.text();
if (bypassResponse.status !== 503) {
  throw new Error(`special-header request expected 503, received ${bypassResponse.status}`);
}
if (!bypassBody.includes("challenge temporarily unavailable")) {
  throw new Error("special-header request did not return the fixed flag-absent response");
}

console.log("desktop AP-01 runtime checks passed");
