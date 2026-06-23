// Example: open the "Ban hosting of pornographic content" proposal, with one PROOF
// argument and one ANTI-PROOF argument (each citing a trusted source).
//
// Runs fully offline against the in-memory MockCe + a deterministic demo signer.
// Point it at a real node by swapping `MockCe` for `new CeClient(...)` and the demo
// signer for a node-key/ce-cap signer.
//
//   node examples/propose-ban-porn.js

import { Governance } from "../src/index.js";
import { MockCe, makeSigner, makeVerifySig } from "./_mock.js";

async function main() {
  const ce = new MockCe({ height: 100 });
  const author = "a".repeat(64); // the proposer's node id (demo)

  const gov = new Governance({
    ce,
    signer: makeSigner("proposer"),
    verifySig: makeVerifySig("proposer"),
    author,
    // no llm => deterministic-only evidence checks (graceful degrade).
  });

  // 1) Open the proposal. close_height defaults to open_height + the voting window.
  const proposal = await gov.createProposal({
    title: "Ban hosting of pornographic content",
    statement: "Hosting of pornographic content is disallowed on the CE mesh.",
    category: "pornographic_content",
    action: "deny",
    expertise_tags: ["legal", "safety", "content-policy"],
  });

  console.log("PROPOSAL");
  console.log("  id:            ", proposal.id);
  console.log("  category:      ", proposal.category);
  console.log("  action:        ", proposal.action);
  console.log("  open_height:   ", proposal.open_height);
  console.log("  close_height:  ", proposal.close_height);
  console.log("  expertise_tags:", proposal.expertise_tags.join(", "));
  console.log("  signed:        ", !!proposal.sig);

  // 2) A PROOF argument (supports the ban), citing a trusted legal source.
  const proof = await gov.argue({
    proposal_id: proposal.id,
    arg_kind: "proof",
    body:
      "Multiple jurisdictions impose hosting-liability and age-verification duties on " +
      "operators of pornographic content; a permissive default exposes hosts to legal risk.",
    sources: [
      {
        url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2065",
        title: "Regulation (EU) 2022/2065 (Digital Services Act)",
        trust: 90,
      },
    ],
  });

  // 3) An ANTI-PROOF argument (opposes the ban), citing a trusted source.
  const antiproof = await gov.argue({
    proposal_id: proposal.id,
    arg_kind: "antiproof",
    body:
      "A categorical content ban is over-broad and risks blocking lawful adult material and " +
      "dual-use research; jurisdiction-specific, opt-in policy is the less restrictive means.",
    sources: [
      {
        url: "https://www.eff.org/issues/free-speech",
        title: "EFF — Free Speech and Intermediary Liability",
        trust: 80,
      },
    ],
  });

  console.log("\nARGUMENTS");
  console.log("  proof.id:    ", proof.id, `(${proof.arg_kind}, ${proof.sources.length} source)`);
  console.log("  antiproof.id:", antiproof.id, `(${antiproof.arg_kind}, ${antiproof.sources.length} source)`);

  // 4) Re-load from the mesh to prove discovery/round-trip via CEP-1 signals + blobs.
  const reloaded = await gov.loadProposal(proposal.id);
  const args = await gov.loadArguments(proposal.id);
  console.log("\nDISCOVERY (reloaded from the mesh)");
  console.log("  proposal round-trips:", reloaded && reloaded.id === proposal.id);
  console.log("  arguments found:     ", args.length, "(", args.map((a) => a.arg_kind).join(", "), ")");

  // 5) Validate each argument's evidence (deterministic-only here).
  console.log("\nEVIDENCE VALIDATION (deterministic)");
  for (const a of args) {
    const v = await gov.validateArgument(a);
    console.log(`  ${a.arg_kind.padEnd(9)} ok=${v.ok} score=${v.score} deterministic=${v.deterministic}`);
  }

  console.log("\nOK: proposal + proof + antiproof created and discoverable.");
  return { proposal, proof, antiproof };
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
