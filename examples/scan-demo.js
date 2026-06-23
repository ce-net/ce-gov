// Example: pre-run policy scan. Screen a fake cryptominer image and a benign image
// against the active policy set, and print the signed ScanVerdicts.
//
// Demonstrates:
//   * the deterministic hard layer (miner binary + stratum string) short-circuits to DENY
//     with NO LLM call (reproducible, the only hard deny),
//   * a benign, open-source artifact escalates to the LLM and is ALLOWED (here a scripted
//     stub stands in for Claude/ce-infer so the demo runs offline),
//   * fail-closed: a benign artifact with NO available LLM is DENIED (a gate that fails open
//     is not a gate),
//   * verdicts are content-addressed, bound to the policy_set_id, broadcast, and cached
//     (a second scan of the same digest+policy returns the cached verdict).
//
//   node examples/scan-demo.js          # offline, scripted LLM stub
//   ANTHROPIC_API_KEY=... node examples/scan-demo.js   # real Claude classifier

import { Governance, isAllowed } from "../src/index.js";
import { defaultPolicySet } from "../src/scan.js";
import { MockCe, makeSigner, makeVerifySig, stubScanLlm } from "./_mock.js";

function printVerdict(label, v) {
  console.log(`\n${label}`);
  console.log("  decision:     ", v.decision, isAllowed(v) ? "(launch permitted)" : "(launch refused)");
  console.log("  categories:   ", v.categories.length ? v.categories.join(", ") : "(none)");
  console.log("  confidence:   ", v.confidence);
  console.log("  deterministic:", v.deterministic);
  console.log("  rationale:    ", v.rationale);
  console.log("  policy_set_id:", v.policy_set_id);
  console.log("  verdict id:   ", v.id);
  if (v.model_id) console.log("  model_id:     ", v.model_id);
}

async function main() {
  const ce = new MockCe({ height: 200 });
  const haveKey = !!(process.env && process.env.ANTHROPIC_API_KEY);

  // The scan classifier: real Claude/ce-infer if a key is present, else a scripted ALLOW
  // stub so the benign path is demonstrable offline. (The miner is caught deterministically
  // and never reaches the LLM regardless.)
  const scanValidator = haveKey ? undefined : stubScanLlm({ decision: "allow", confidence: 92, rationale: "benign web service; no banned-category intent" });

  const gov = new Governance({
    ce,
    signer: makeSigner("scanner"),
    verifySig: makeVerifySig("scanner"),
    scanValidator,
  });

  // Screen against the DEFAULT banned set (cryptomining, ddos, ..., pornographic_content).
  // In production the active set is the output of voting (see tally-demo); here we inject
  // the documented defaults so the deterministic miner deny is demonstrable standalone.
  const scanOpts = { activePolicySet: async () => defaultPolicySet() };

  console.log(`Scan classifier: ${haveKey ? "Claude (ANTHROPIC_API_KEY set)" : "offline stub (no key)"}`);
  console.log("Active policy set: default banned categories (cryptomining, ddos, ... , pornographic_content)");

  // 1) A fake cryptominer image: xmrig + a stratum pool URL in the cmd.
  const minerVerdict = await gov.scanArtifact({
    artifact_type: "docker",
    artifact_digest: "1".repeat(64),
    source_url: "https://github.com/xmrig/xmrig",
    cmd: ["xmrig", "-o", "stratum+tcp://pool.minexmr.com:4444", "--donate-level", "1"],
    env_keys: ["WALLET"],
    cpu_cores: 8,
    mem_mb: 512,
    payer: "b".repeat(64),
  }, scanOpts);
  printVerdict("MINER IMAGE  (xmrig + stratum)", minerVerdict);

  // 2) A benign open-source web service.
  const benignVerdict = await gov.scanArtifact({
    artifact_type: "docker",
    artifact_digest: "2".repeat(64),
    source_url: "https://github.com/caddyserver/caddy",
    cmd: ["caddy", "run", "--config", "/etc/caddy/Caddyfile"],
    env_keys: ["CADDY_ADMIN"],
    cpu_cores: 2,
    mem_mb: 256,
    payer: "b".repeat(64),
  }, scanOpts);
  printVerdict("BENIGN IMAGE (caddy web server)", benignVerdict);

  // 3) Cache check: re-scan the miner digest -> the same cached verdict id.
  const minerAgain = await gov.scanArtifact({
    artifact_type: "docker",
    artifact_digest: "1".repeat(64),
    source_url: "https://github.com/xmrig/xmrig",
    cmd: ["xmrig"],
    cpu_cores: 8,
    mem_mb: 512,
    payer: "b".repeat(64),
  }, scanOpts);
  console.log("\nCACHE");
  console.log("  re-scan returns cached verdict:", minerAgain.id === minerVerdict.id);

  // 4) Fail-closed demonstration: a benign artifact with NO LLM available => DENY.
  const failClosed = new Governance({ ce: new MockCe({ height: 200 }), signer: makeSigner("fc") });
  // force the degraded (none) backend
  failClosed.scanValidator = (await import("../src/scan.js")).makeScanValidator({ backend: "none" });
  const noLlm = await failClosed.scanArtifact({
    artifact_type: "docker",
    artifact_digest: "3".repeat(64),
    source_url: "https://github.com/some/benign",
    cmd: ["./serve"],
    cpu_cores: 1,
    mem_mb: 128,
    payer: "b".repeat(64),
  }, scanOpts);
  printVerdict("FAIL-CLOSED  (benign, no LLM available)", noLlm);

  console.log("\nSUMMARY");
  console.log("  miner  ->", minerVerdict.decision, "(deterministic hard-deny, no LLM call)");
  console.log("  benign ->", benignVerdict.decision, haveKey ? "(LLM)" : "(LLM stub)");
  console.log("  no-LLM ->", noLlm.decision, "(fail-closed)");
  console.log("\nOK: pre-run scan screened both artifacts.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
