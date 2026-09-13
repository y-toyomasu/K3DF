import fs from "node:fs";

const flagPath = "/run/k3df-flags/flag-1/flag.value";

export async function getServerSideProps() {
  try {
    const flag = fs.readFileSync(flagPath, "utf8").trim();
    return { props: { flag } };
  } catch {
    return { notFound: true };
  }
}

export default function ProtectedChallenge({ flag }) {
  return <main>{flag}</main>;
}
