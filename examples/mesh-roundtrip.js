// @ce-net/gov example — the MESH ROUNDTRIP (NO NETWORK, two simulated nodes).
//
// Demonstrates the real mesh-app data plane the conversion introduced, end to end:
//
//   Node A creates a proposal  -> stores it as a content-addressed BLOB
//                              -> announces { type, id, cid, height } on the gov pubsub topic
//   Node B is subscribed       -> receives the event on its mesh stream (live feed)
//                              -> GETs the blob by cid to MATERIALIZE the proposal
//   Node B (fresh)             -> fetchIndex over request/reply to A's advertised service
//                                 to CATCH UP without having seen the live event
//
// It uses `makeFakeMesh()` from src/mesh.js, which models the node's real routing
// semantics (pubsub auto-subscribe + inbound-on-stream; request/reply via reply_token;
// DHT advertise/find; content-addressed blobs). The SAME application code paths
// (proposals.createProposal, mesh.watchEvents, mesh.fetchIndex, mesh-service.startGovService)
// run against a live node — only the transport object is swapped. Run:
//
//   node examples/mesh-roundtrip.js
//
// Against TWO real local nodes instead, construct `new CeClient({ base, token })` for each
// (with the node's api.token) and run the identical flow; against ONE node + the relay,
// point both clients at the relay's /mesh/* and you will see the event cross the wire.

import { makeFakeMesh, GOV_TOPIC, GOV_SERVICE, watchEvents, fetchIndex, EV } from "../src/mesh.js";
import { startGovService } from "../src/mesh-service.js";
import { createProposal, loadProposal, listProposals } from "../src/proposals.js";
import { makeSigner } from "./_mock.js";

const dec = new TextDecoder();

// --- build two mesh-capable clients over the in-memory fabric --------------
// Each "client" gets the mesh methods from makeFakeMesh plus the small extra surface the
// governance modules need (status/beacon/history and the pluggable putBlob/getBlob mapped
// onto the mesh blob store). This is exactly the shape src/ce.js's CeClient exposes.
const fabric = makeFakeMesh();

function govClient(nodeId, height) {
  const m = fabric.client(nodeId);
  return Object.assign(m, {
    async status() { return { node_id: nodeId, height, balance: "0" }; },
    async beacon() { return { height, hash: "f".repeat(64) }; },
    async history() { return {}; },
    // Map the modules' pluggable blob API onto the real mesh blob store.
    async putBlob(bytes) { return m.meshPutBlob(bytes); },
    async getBlob(cid) { return m.meshGetBlob(cid); },
  });
}

const nodeA = govClient("aaaa", 100);
const nodeB = govClient("bbbb", 100);
const signer = makeSigner("nodeA");

async function main() {
  console.log("CE-GOV mesh roundtrip (two simulated nodes over the real mesh primitives)\n");

  // 1) Node B runs the governance service: advertises ce-gov.v1, subscribes to the topic,
  //    indexes announced CIDs, answers index/get/validate queries. (Either node can host it;
  //    here B hosts so A's create + announce flow into B's index live.)
  const svc = await startGovService(nodeB, { readvertiseMs: 0 });
  console.log("Node B service up:");
  console.log("  advertises:", svc.serviceNames.join(", "));
  console.log("  subscribes:", svc.topics.join(", "), "\n");

  // 2) Node B also runs a live UI-style feed: print every governance event it sees.
  const live = [];
  const feed = watchEvents(nodeB, (ev) => {
    live.push(ev);
    console.log(`  [B live feed] event type=${ev.type} id=${ev.id.slice(0, 12)}… cid=${ev.cid.slice(0, 12)}… height=${ev.height}`);
  });

  // 3) Node A creates a proposal. createProposal stores the blob (POST /blobs) and announces
  //    the index event on the gov topic (POST /mesh/publish) — no signals, no hub /db.
  console.log("Node A creates a proposal…");
  const proposal = await createProposal(
    nodeA,
    {
      title: "Ban pornographic hosting",
      statement: "Hosting of pornographic content is disallowed on the mesh.",
      category: "pornographic_content",
      action: "deny",
      expertise_tags: ["legal", "safety"],
      author: "a".repeat(64),
    },
    signer,
  );
  console.log(`  proposal id=${proposal.id.slice(0, 16)}…  (stored as blob + announced)\n`);

  // let the in-process delivery settle (a real node delivers over gossipsub on the SSE).
  await fabric.flush();

  // 4) Node B materializes the proposal it heard about, straight from the blob by cid.
  console.log("Node B materializes the announced proposal from its blob cid…");
  const seen = live.find((e) => e.type === EV.PROPOSAL);
  if (!seen) throw new Error("expected B to receive the proposal event");
  const bytes = await nodeB.meshGetBlob(seen.cid);
  const materialized = JSON.parse(dec.decode(bytes));
  console.log(`  materialized: "${materialized.title}" (${materialized.category} -> ${materialized.action})\n`);
  if (materialized.id !== proposal.id) throw new Error("materialized id mismatch");

  feed.close();

  // 5) Catch-up: a FRESH node C that never saw the live event asks A/B's service for the
  //    index over request/reply, then back-fills the proposal by cid. No central store.
  console.log("Fresh Node C catches up via request/reply to the discovered service…");
  const nodeC = govClient("cccc", 100);
  const index = await fetchIndex(nodeC, { timeout_ms: 2000 });
  console.log(`  fetchIndex(${GOV_SERVICE}) returned ${index.length} entr${index.length === 1 ? "y" : "ies"}`);
  const entry = index.find((e) => e.type === EV.PROPOSAL);
  if (!entry) throw new Error("expected the catch-up index to contain the proposal");
  const caughtUp = await loadProposal(nodeC, entry.id);
  console.log(`  loadProposal -> "${caughtUp && caughtUp.title}" (caught up without seeing the live event)\n`);
  if (!caughtUp || caughtUp.id !== proposal.id) throw new Error("Node C failed to catch up");

  // 6) listProposals on C now enumerates from its (mesh-filled) index.
  const all = await listProposals(nodeC);
  console.log(`Node C listProposals -> ${all.length} proposal(s) discovered over the mesh.`);

  svc.stop();
  console.log("\nOK: create -> announce -> live materialize -> request/reply catch-up, all over the mesh.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
