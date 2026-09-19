import { StubNotice } from "@/components/ui";

export function Agents() {
  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-xl font-semibold">Agents</h1>
      <StubNotice title="Agent enrollment and sensor management" task="T-101a">
        Not built. The deployed agent binary exists (poll loop, mTLS client, collectors wired,
        per-OS build) and can be frozen with <code>make build-agent</code>, but the backend that
        issues single-use enrollment tokens and stores agent identities (T-073a) does not, so there
        is nothing truthful to list here.
      </StubNotice>
    </div>
  );
}
