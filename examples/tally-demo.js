// Example: simulate reputation-weighted, quadratic-damped voting on the "ban porn"
// proposal and print the verdict.
//
// Demonstrates:
//   * weight is DERIVED from each voter's /history reputation (not declared),
//   * quadratic damping caps whale dominance,
//   * a well-supported PROOF argument folds into the FOR tally,
//   * quorum + supermajority decide; the result is a signed Verdict,
//   * the Verdict enacts the active Policy that the pre-run scan screens against.
//
// Runs fully offline (in-memory CE + deterministic signer + scripted reputations).
//
//   node examples/tally-demo.js

import { Governance, Amount } from "../src/index.js";
import { MockCe, makeSigner, makeVerifySig } from "./_mock.js";

const C = 1_000_000_000_000_000_000n; // 1 credit in base units

// A MockCe that serves per-node /history so reputation.js derives real vote weight.
class RepCe extends MockCe {
  constructor(histories, opts) {
    super(opts);
    this._hist = histories; // nodeId -> NodeStats
  }
  async history(nodeId) {
    return this._hist[nodeId] || {};
  }
}

function voterId(n) {
  return String(n).repeat(64).slice(0, 64);
}

async function main() {
  // Five voters with different earned-work histories (=> different reputation weight).
  // A "whale" with 100 credits earned and four ordinary contributors with 1-4 credits.
  const histories = {
    [voterId(1)]: { earned: (100n * C).toString(), recent_earned: (100n * C).toString(), jobs_hosted: 50 }, // whale, FOR
    [voterId(2)]: { earned: (4n * C).toString(), recent_earned: (4n * C).toString(), jobs_hosted: 20 },      // FOR
    [voterId(3)]: { earned: (3n * C).toString(), recent_earned: (3n * C).toString(), jobs_hosted: 12 },      // FOR
    [voterId(4)]: { earned: (2n * C).toString(), recent_earned: (2n * C).toString(), jobs_hosted: 8 },       // FOR
    [voterId(5)]: { earned: (3n * C).toString(), recent_earned: (3n * C).toString(), jobs_hosted: 10 },      // AGAINST
    [voterId(6)]: { earned: (5n * C).toString(), recent_earned: (5n * C).toString(), jobs_hosted: 18 },      // argument author
  };

  const ce = new RepCe(histories, { height: 100, beaconHash: "f".repeat(64) });
  const proposer = "a".repeat(64);

  const gov = new Governance({
    ce,
    signer: makeSigner("gov"),
    verifySig: makeVerifySig("gov"),
    author: proposer,
    allowUnsigned: false, // votes are signed by the demo signer and verified in the tally
  });

  // 1) Open the proposal (short window so we can close it).
  const proposal = await gov.createProposal({
    title: "Ban hosting of pornographic content",
    statement: "Hosting of pornographic content is disallowed on the CE mesh.",
    category: "pornographic_content",
    action: "deny",
    expertise_tags: ["legal", "safety"],
    open_height: 100,
    close_height: 110,
  });

  // 2) A PROOF argument with a trusted source (will fold into FOR).
  const proof = await gov.argue({
    proposal_id: proposal.id,
    arg_kind: "proof",
    author: voterId(6),
    body: "Several jurisdictions place hosting-liability duties on operators of such content.",
    sources: [
      { url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2065", title: "EU DSA", trust: 90 },
    ],
  });

  // 3) Cast votes. Each voter's weight is derived from its /history (tags weight expertise).
  const tags = proposal.expertise_tags;
  const cast = [];
  for (const n of [1, 2, 3, 4]) {
    cast.push(await gov.vote(
      { proposal_id: proposal.id, direction: "up", author: voterId(n) },
      { expertise_tags: tags },
    ));
  }
  // one AGAINST voter
  cast.push(await gov.vote(
    { proposal_id: proposal.id, direction: "down", author: voterId(5) },
    { expertise_tags: tags },
  ));
  // two upvotes on the PROOF argument (boost its community score)
  cast.push(await gov.vote(
    { proposal_id: proposal.id, argument_id: proof.id, direction: "up", author: voterId(2) },
    { expertise_tags: tags },
  ));
  cast.push(await gov.vote(
    { proposal_id: proposal.id, argument_id: proof.id, direction: "up", author: voterId(3) },
    { expertise_tags: tags },
  ));

  console.log("VOTES CAST");
  for (const v of cast) {
    const target = v.argument_id ? `arg ${v.argument_id.slice(0, 8)}` : "proposal";
    console.log(
      `  ${v.author.slice(0, 4)}  ${v.direction.padEnd(4)}  ${target.padEnd(14)}  ` +
        `raw=${Amount.toCredits(v.weight)} cr`,
    );
  }

  // 4) Tally (open window allowed; just computes the outcome).
  const t = await gov.tally(proposal, cast, [proof]);
  console.log("\nTALLY (quadratic-damped, evidence-gated)");
  console.log("  voter_count: ", t.voter_count);
  console.log("  tally_for:   ", Amount.toCredits(t.tally_for), "cr (damped)");
  console.log("  tally_against", Amount.toCredits(t.tally_against), "cr (damped)");
  console.log("  quorum_met:  ", t.quorum_met);
  console.log("  passed:      ", t.passed);
  console.log("  decision:    ", t.decision);

  // 5) Close the window and finalize a signed Verdict (needs height > close_height).
  ce._height = 111;
  const verdict = await gov.finalize(proposal, cast, [proof]);
  console.log("\nVERDICT");
  console.log("  id:          ", verdict.id);
  console.log("  decision:    ", verdict.decision);
  console.log("  tally_for:   ", Amount.toCredits(verdict.tally_for), "cr");
  console.log("  tally_against", Amount.toCredits(verdict.tally_against), "cr");
  console.log("  beacon_height", verdict.beacon_height);
  console.log("  signed:      ", !!verdict.sig);

  // 6) Enact -> Policy -> active policy set -> Guardian banned_categories export.
  if (verdict.decision === "deny") {
    const policy = await gov.enact(verdict, proposal);
    const set = await gov.activePolicy();
    const guard = await gov.guardPolicyExport(set);
    console.log("\nENACTED POLICY");
    console.log("  policy.category:    ", policy.category, `(action: ${policy.action})`);
    console.log("  policy_set_id:      ", set.id);
    console.log("  guard banned_cats:  ", guard.banned_categories.join(", "));
    console.log("\nThis active set is exactly what the pre-run scan + node Guardian screen against.");
  }

  console.log("\nOK: weighted tally produced a verdict and (on pass) an enacted policy.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
