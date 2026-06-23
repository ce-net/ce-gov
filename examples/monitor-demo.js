// Example: runtime monitoring. Watch the mesh signal stream, detect an abusive job
// (sustained-100%-CPU hashing profile => cryptomining), and auto-file a signed,
// beacon-stamped AbuseReport — WITHOUT ever enforcing or auto-slashing.
//
// Demonstrates:
//   * pure detectors turn a job-metering sample into a Finding,
//   * an AbuseReport is only accepted against an ENACTED policy category (closes the loop
//     with voting): we first enact a "cryptomining" deny policy,
//   * the report is content-addressed, signed, beacon-stamped, and broadcast as CEP-1,
//   * it feeds the reputation layer as a NEGATIVE karma signal (advisory only),
//   * the proposed on-chain trigger is a BONDED ANNOTATION, not a slash (onchain-spec §2.5).
//
//   node examples/monitor-demo.js

import { Governance, reputationFeed } from "../src/index.js";
import { MockCe, makeSigner, makeVerifySig } from "./_mock.js";

async function main() {
  const ce = new MockCe({ height: 300, beaconHash: "f".repeat(64) });
  const operator = "a".repeat(64);

  const gov = new Governance({
    ce,
    signer: makeSigner("operator"),
    verifySig: makeVerifySig("operator"),
    author: operator,
  });

  // 0) Enact a "cryptomining" deny policy so an abuse report against it is meaningful.
  //    (In production this comes from a passing governance Verdict; here we craft the
  //    Verdict+Proposal directly to seed the active set.)
  const proposal = await gov.createProposal({
    title: "Ban cryptomining workloads",
    statement: "Unpaid sustained all-core hashing for external pools is disallowed.",
    category: "cryptomining",
    action: "deny",
    expertise_tags: ["security"],
    open_height: 300,
    close_height: 305,
  });
  ce._height = 306;
  // finalize with no votes => fails quorum; for the demo we synthesize a passing Verdict
  // by enacting directly from a deny-decision verdict object bound to this proposal.
  const verdict = {
    kind: "verdict",
    proposal_id: proposal.id,
    decision: "deny",
    tally_for: "0",
    tally_against: "0",
    voter_count: 0,
    beacon_height: 306,
    beacon_hash: "f".repeat(64),
    state: "closed",
    ts: Date.now(),
    author: operator,
  };
  const { finalize } = await import("../src/types.js");
  const signedVerdict = await finalize(verdict, makeSigner("operator"));
  await gov.enact(signedVerdict, proposal);
  const set = await gov.activePolicy();
  console.log("ACTIVE POLICY");
  console.log("  banned:", (await gov.guardPolicyExport(set)).banned_categories.join(", "));

  // 1) Start the monitor. onSuspect fires on a detector hit; onReport on an auto-filed report.
  const suspects = [];
  const reports = [];
  const handle = gov.monitor({
    onSuspect: (s) => {
      suspects.push(s);
      console.log(
        `\nSUSPECT  job=${s.sample.job_id.slice(0, 8)} host=${s.sample.host.slice(0, 8)} ` +
          `-> ${s.finding.category} (severity ${s.finding.severity})`,
      );
      console.log("  evidence:", s.finding.evidence);
    },
    onReport: (r) => {
      reports.push(r);
      console.log("\nABUSE REPORT FILED");
      console.log("  id:           ", r.id);
      console.log("  host:         ", r.host);
      console.log("  category:     ", r.category);
      console.log("  severity:     ", r.severity);
      console.log("  beacon_height:", r.beacon_height);
      console.log("  signed:       ", !!r.sig);
    },
    onError: (e) => console.error("monitor error:", e.message),
  });

  // 2) Inject synthetic job-metering signals. `monitor.sampleFromSignal` reads the metering
  //    fields off `signal.job` (or `.metering`/`.sample`), so we attach them directly.
  //    First: sustained 99% CPU, 300s, ~no IO => the classic miner hashing-loop profile.
  const host = "b".repeat(64);
  const job = "c".repeat(64);
  const digest = "d".repeat(64);
  ce.inject({
    from: host,
    job: { job_id: job, host, artifact_digest: digest, cpu_pct: 99, sustained_secs: 300, io_bytes: 1024 },
  });
  // Second: a benign job (low CPU, high IO) => NOT flagged.
  ce.inject({
    from: host,
    job: { job_id: "e".repeat(64), host, cpu_pct: 12, sustained_secs: 300, io_bytes: 50_000_000 },
  });

  // Let async report-filing settle.
  await new Promise((r) => setTimeout(r, 50));
  handle.close();

  // 3) Reputation feed: the report down-weights the host (advisory; touches no consensus).
  const collected = await gov.collectReports({ host });
  const feed = reputationFeed(collected);
  console.log("\nREPUTATION FEED (advisory karma deltas)");
  console.log("  ", JSON.stringify(feed));

  // 4) The proposed on-chain trigger payload: a bonded annotation, NOT a slash.
  if (reports.length) {
    const tx = await gov.slashTriggerPayload(reports[0], { stake: "1000000000000000000" }); // 1 credit stake
    console.log("\nPROPOSED ON-CHAIN TRIGGER (bonded annotation, NOT a slash)");
    console.log("  tx_type:        ", tx.tx_type);
    console.log("  reporter:       ", tx.reporter.slice(0, 8) + "...");
    console.log("  artifact_digest:", tx.artifact_digest.slice(0, 8) + "...");
    console.log("  host:           ", tx.host.slice(0, 8) + "...");
    console.log("  category:       ", tx.category);
    console.log("  stake:          ", tx.stake, "(refundable; forfeit if a re-scan contradicts)");
  }

  console.log("\nSUMMARY");
  console.log("  suspects detected:", suspects.length, "(1 miner, benign job ignored)");
  console.log("  reports filed:    ", reports.length);
  console.log("\nOK: monitor observed, detected, and reported — never enforced, never slashed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
