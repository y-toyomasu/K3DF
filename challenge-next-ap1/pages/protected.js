import fs from "node:fs";

const flagPath = "/run/k3df-flags/flag-1/flag.value";

export async function getServerSideProps({ res }) {
  try {
    const flag = fs.readFileSync(flagPath, "utf8").trim();
    return { props: { flag } };
  } catch {
    res.statusCode = 503;
    return { props: { flag: null } };
  }
}

export default function ProtectedChallenge({ flag }) {
  if (!flag) return <main>challenge temporarily unavailable</main>;
  return <main>{flag}</main>;
}
