// @ce-net/gov — (c) tally + verdict engine.
//
// "Reddit for experts": members upvote/downvote a PROPOSAL directly, and they
// upvote/downvote individual ARGUMENTS (proof / antiproof). Every vote carries a
// RAW reputation weight (base-unit string) derived from `reputation.js`. The tally:
//
//   1. Verifies vote signatures (via an injected verifier) and discards bad ones.
//   2. Dedupes per (author, target) — last-write-wins by ts/id — so one identity
//      counts once per proposal and once per argument (whale-of-sockpuppets still
//      needs distinct identities, which CE's bond/trust substrate makes costly).
//   3. Applies QUADRATIC damping per identity: effective = isqrt(raw). A whale with
//      100x the raw weight of a minnow ends up with only 10x the vote — plutocracy
//      damping while still rewarding earned reputation.
//   4. Folds ARGUMENT scores into the proposal tally: a well-supported proof adds to
//      `for`, a well-supported antiproof adds to `against`, each scaled by the
//      argument's net (damped) community score AND by whether its cited sources are
//      verified (via the injected validator's `verifyEvidence`). Unsupported
//      arguments (no verified sources) contribute nothing.
//   5. Decides via QUORUM (min distinct voters) + SUPERMAJORITY (share of total
//      weight). Below quorum, or a tie / sub-supermajority => the proposal FAILS
//      (status-quo wins; CE is permissive by default, a policy must clear the bar).
//
// A passing proposal produces a signed `Verdict` (the active-policy authority record),
// stamped with the current beacon for auditability. `policy.js` turns that Verdict
// into a `Policy` and the Guardian `banned_categories` export.
//
// PURITY: every helper that can be pure is pure and takes plain data. The only IO
// functions take an injected `CeClient`. The signature verifier and the validator
// are injected (never constructed here) so this module has no static dependency on
// `validator.js` (owned by another implementer) and stays unit-testable offline.

import {
  makeVote,
  makeVerdict,
  finalize,
  artifactId,
  Amount,
  VOTE_DIR,
  DECISION,
  STATE,
  ARG_KIND,
} from "./types.js";
import { profile, rawWeight } from "./reputation.js";
import { announce as meshAnnounce, EV } from "./mesh.js";

/**
 * Announce a freshly-stored vote/verdict over the governance mesh so peers see it live and
 * can rebuild tallies without polling. Best-effort + no-op for mesh-less clients (the cid
 * carried by the event is the pointer; the blob is the source of truth). The blob `cid`
 * here is the sha256 of the stored bytes, which equals what `ce.meshPutBlob` returns.
 * @param {import("./ce.js").CeClient} ce
 * @param {{type:string,id:string,cid:string,height?:number}} ev
 */
async function announceArtifact(ce, ev) {
  if (!ce || typeof ce.meshPublish !== "function") return;
  try {
    await meshAnnounce(ce, ev);
  } catch {
    /* best-effort */
  }
}

// ---------------------------------------------------------------------------
// Tunable thresholds (documented module constants)
// ---------------------------------------------------------------------------

/** Tally / decision parameters. All integer; shares are basis points (1e4 = 100%). */
export const TALLY = Object.freeze({
  // Minimum number of DISTINCT verified voters on the proposal for the result to count.
  QUORUM_VOTERS: 3,
  // Minimum effective weight (post-quadratic, base units) the winning side must reach.
  // Guards against a quorum of dust-weight identities passing a policy.
  QUORUM_WEIGHT: Amount.fromCredits("1"), // 1 credit-equivalent of damped weight
  // Supermajority required to PASS, in basis points of (for+against) effective weight.
  // 6000 = 60%. Ties and anything below this fail (status quo wins).
  SUPERMAJORITY_BPS: 6000,
  // An argument only contributes to the tally if its damped net community score is at
  // least this many base units AND its evidence is validator-supported.
  ARG_MIN_NET_WEIGHT: Amount.fromCredits("0.25"),
  // How much an accepted argument's net score is scaled into the proposal tally,
  // expressed in basis points (5000 = arguments count half as much as direct votes).
  ARG_TALLY_BPS: 5000,
  // Source-trust (0..100) gate below which an argument's evidence is treated as
  // unverified even if the validator returns supported (defense in depth).
  MIN_SOURCE_TRUST: 25,
});

const BPS = 10000n;

// ---------------------------------------------------------------------------
// Pure integer math
// ---------------------------------------------------------------------------

/**
 * Integer square root of a non-negative BigInt (Newton's method). Deterministic,
 * no floats. `isqrt(n)` is the floor of the real square root.
 * @param {bigint} n
 * @returns {bigint}
 */
export function isqrt(n) {
  if (typeof n !== "bigint") throw new TypeError("isqrt expects a BigInt");
  if (n < 0n) throw new RangeError("isqrt of negative");
  if (n < 2n) return n;
  // Initial guess: 2^(ceil(bits/2)).
  let x = n;
  let y = (x + 1n) >> 1n;
  while (y < x) {
    x = y;
    y = (x + n / x) >> 1n;
  }
  return x;
}

/**
 * Quadratic (whale-damping) transform of a RAW base-unit weight string.
 * Because raw weight is in base units (10^18 per credit), a naive isqrt would
 * collapse everything to ~1e9; we keep the result in base units by multiplying
 * back up by sqrt(CREDIT) so that quadratic weight stays comparable in scale:
 *   quad(raw) = isqrt(raw) * isqrt(CREDIT)   (still floor, still integer).
 * This makes quad(k^2 * x) ≈ k * quad(x): doubling raw weight ~1.41x the vote.
 * @param {string} rawAmount base-unit decimal string
 * @returns {string} damped base-unit decimal string
 */
export function quadWeight(rawAmount) {
  const raw = Amount.toBig(rawAmount);
  if (raw <= 0n) return "0";
  // CREDIT = 10^18; isqrt(10^18) = 10^9 exactly.
  const SQRT_CREDIT = 1_000_000_000n;
  return Amount.fromBig(isqrt(raw) * SQRT_CREDIT);
}

// ---------------------------------------------------------------------------
// Vote casting (IO: needs beacon + reputation + broadcast)
// ---------------------------------------------------------------------------

/**
 * Cast a vote on a proposal (or on a specific argument when `fields.argument_id`
 * is set). Stamps the current beacon, derives the voter's RAW reputation weight
 * for the proposal's expertise tags, then finalize()s and broadcasts it.
 *
 * The RAW weight is stored on the vote; quadratic damping is applied at tally time
 * (so a re-tally with a different policy can't be gamed by pre-baking damped weight).
 *
 * @param {import("./ce.js").CeClient} ce
 * @param {Partial<import("./types.js").Vote>} fields  must include proposal_id, direction, author
 * @param {(payload: string) => Promise<string>} signer
 * @param {Object} [opts]
 * @param {string[]} [opts.expertise_tags]  tags to weight reputation by (from the proposal)
 * @param {string} [opts.weight]            override raw weight (tests); else derived from /history
 * @returns {Promise<import("./types.js").Vote>}
 */
export async function castVote(ce, fields, signer, opts = {}) {
  if (!fields || !fields.proposal_id) throw new TypeError("castVote: proposal_id required");
  if (!fields.author) throw new TypeError("castVote: author required");
  if (!Object.values(VOTE_DIR).includes(fields.direction)) {
    throw new TypeError(`castVote: direction must be ${Object.values(VOTE_DIR).join("|")}`);
  }

  // Beacon provenance (anti-grind): bind the vote to a recent chain randomness point.
  let beacon_height = fields.beacon_height | 0;
  let beacon_hash = fields.beacon_hash;
  if (beacon_hash === undefined) {
    const b = await ce.beacon();
    beacon_height = (b && b.height) | 0;
    beacon_hash = (b && b.hash) || "0".repeat(64);
  }

  // Raw reputation weight. Caller may inject (tests); otherwise derive from /history.
  let weight = opts.weight ?? fields.weight;
  if (weight === undefined) {
    const tags = opts.expertise_tags || [];
    const prof = await profile(ce, fields.author, { tags });
    weight = rawWeight(prof, tags);
  }

  const vote = makeVote({
    proposal_id: fields.proposal_id,
    argument_id: fields.argument_id,
    direction: fields.direction,
    weight,
    beacon_height,
    beacon_hash,
    ts: fields.ts,
    author: fields.author,
  });

  const finalized = await finalize(vote, signer);
  // Persist the vote as a content-addressed blob, then announce its cid on the governance
  // mesh topic so peers see it live and can fold it into tallies (REPLACES polling).
  try {
    const bytes = new TextEncoder().encode(JSON.stringify(finalized));
    const cid = await ce.putBlob(bytes);
    await announceArtifact(ce, { type: EV.VOTE, id: finalized.id, cid, height: beacon_height });
  } catch {
    /* blob store optional; the announce is best-effort */
  }
  return finalized;
}

// ---------------------------------------------------------------------------
// Signature verification + dedup (pure given an injected verifier)
// ---------------------------------------------------------------------------

/**
 * Default signature verifier: if a vote carries no `sig`, treat as unverified
 * (rejected) UNLESS `opts.allowUnsigned` is set (local tests / unsigned tallies).
 * Real deployments inject a verifier backed by ce-cap / node identity.
 * @param {(payload:string, sig:string, author:string)=>Promise<boolean>|boolean} [verifySig]
 * @param {{allowUnsigned?:boolean}} [opts]
 */
function makeVerify(verifySig, opts = {}) {
  return async (artifact) => {
    if (!artifact || typeof artifact !== "object") return false;
    if (!artifact.sig) return !!opts.allowUnsigned;
    if (!verifySig) return !!opts.allowUnsigned; // no verifier wired => only pass if explicitly allowed
    // Recompute the content id; a tampered artifact will not match its declared id.
    const expectId = await artifactId(artifact);
    if (artifact.id && artifact.id !== expectId) return false;
    const payload = `ce-gov-v1:${artifact.kind}:${canonicalRest(artifact)}`;
    return !!(await verifySig(payload, artifact.sig, artifact.author));
  };
}

// Recompute the signing payload's canonical "rest" exactly as types.signingPayload does,
// without importing the private helper: signingPayload = `${GOV_DOMAIN}:${kind}:${canonical(rest)}`.
// We strip id+sig and canonicalize. (Kept local to avoid coupling to types internals beyond the
// documented contract.)
function canonicalRest(artifact) {
  const { id, sig, ...rest } = artifact;
  return canonicalJSON(rest);
}
function canonicalJSON(value) {
  return JSON.stringify(sortDeep(value));
}
function sortDeep(v) {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(sortDeep);
  const out = {};
  for (const k of Object.keys(v).sort()) {
    if (v[k] === undefined) continue;
    out[k] = sortDeep(v[k]);
  }
  return out;
}

/**
 * Dedupe votes to one per (author, target). Target = argument_id || "proposal".
 * Last-write-wins by (ts, then id) so a voter can change their mind. Filters to
 * the given proposal. Pure.
 * @param {import("./types.js").Vote[]} votes
 * @param {string} proposalId
 * @returns {import("./types.js").Vote[]}
 */
export function dedupeVotes(votes, proposalId) {
  const best = new Map();
  for (const v of votes || []) {
    if (!v || v.proposal_id !== proposalId) continue;
    if (!Object.values(VOTE_DIR).includes(v.direction)) continue;
    const target = v.argument_id || "__proposal__";
    const key = `${v.author}|${target}`;
    const cur = best.get(key);
    if (!cur || laterThan(v, cur)) best.set(key, v);
  }
  return [...best.values()];
}

function laterThan(a, b) {
  const at = a.ts | 0;
  const bt = b.ts | 0;
  if (at !== bt) return at > bt;
  // Stable tiebreak by id so the result is deterministic regardless of input order.
  return String(a.id || "") > String(b.id || "");
}

// ---------------------------------------------------------------------------
// Tally
// ---------------------------------------------------------------------------

/**
 * Compute a proposal's outcome from its votes and arguments.
 *
 * @param {import("./ce.js").CeClient} ce
 * @param {import("./types.js").PolicyProposal} proposal
 * @param {import("./types.js").Vote[]} votes
 * @param {import("./types.js").Argument[]} args
 * @param {Object} [opts]
 * @param {(payload:string,sig:string,author:string)=>Promise<boolean>|boolean} [opts.verifySig]
 * @param {boolean} [opts.allowUnsigned]   accept unsigned votes (tests/local)
 * @param {{verifyEvidence:(arg:any)=>Promise<{supported:boolean,sourceTrust:number,confidence:number}>}} [opts.validator]
 *        injected validator.js adapter; if absent, evidence is judged deterministically from sources.
 * @returns {Promise<{tally_for:string, tally_against:string, voter_count:number, decision:'allow'|'deny'|null, passed:boolean, quorum_met:boolean}>}
 *          decision is the proposal.action ('allow'|'deny') when it passes, else null.
 */
export async function tally(ce, proposal, votes, args, opts = {}) {
  const verify = makeVerify(opts.verifySig, { allowUnsigned: !!opts.allowUnsigned });

  // --- 1) verify + dedupe direct votes and argument votes -----------------
  const verified = [];
  for (const v of votes || []) {
    if (await verify(v)) verified.push(v);
  }
  const deduped = dedupeVotes(verified, proposal.id);

  // Split into direct (proposal) votes and per-argument votes.
  const directVotes = [];
  const argVotesByArg = new Map(); // argId -> Vote[]
  const voters = new Set();
  for (const v of deduped) {
    voters.add(v.author);
    if (v.argument_id) {
      if (!argVotesByArg.has(v.argument_id)) argVotesByArg.set(v.argument_id, []);
      argVotesByArg.get(v.argument_id).push(v);
    } else {
      directVotes.push(v);
    }
  }

  // --- 2) direct proposal tally (quadratic per identity) ------------------
  let forBig = 0n;
  let againstBig = 0n;
  for (const v of directVotes) {
    const w = Amount.toBig(quadWeight(v.weight));
    if (v.direction === VOTE_DIR.UP) forBig += w;
    else againstBig += w;
  }

  // --- 3) fold arguments in, scaled by verified evidence + community score
  const evidence = opts.validator && typeof opts.validator.verifyEvidence === "function"
    ? (a) => opts.validator.verifyEvidence(a)
    : deterministicEvidence;

  for (const arg of args || []) {
    if (!arg || arg.proposal_id !== proposal.id || !arg.id) continue;
    // community net score for this argument (damped per identity).
    const av = argVotesByArg.get(arg.id) || [];
    let net = 0n;
    for (const v of av) {
      const w = Amount.toBig(quadWeight(v.weight));
      net += v.direction === VOTE_DIR.UP ? w : -w;
    }
    if (net < Amount.toBig(TALLY.ARG_MIN_NET_WEIGHT)) continue; // weak/contested argument: ignore

    // evidence gate.
    const ev = await evidence(arg);
    if (!ev || !ev.supported) continue;
    if ((ev.sourceTrust | 0) < TALLY.MIN_SOURCE_TRUST) continue;

    // contribution = net * ARG_TALLY_BPS / 1e4, routed by proof/antiproof.
    const contrib = (net * BigInt(TALLY.ARG_TALLY_BPS)) / BPS;
    if (arg.arg_kind === ARG_KIND.PROOF) forBig += contrib;
    else if (arg.arg_kind === ARG_KIND.ANTIPROOF) againstBig += contrib;
  }

  // --- 4) quorum + supermajority decision ---------------------------------
  const total = forBig + againstBig;
  const voter_count = voters.size;
  const quorumWeight = Amount.toBig(TALLY.QUORUM_WEIGHT);
  const winningSide = forBig > againstBig ? forBig : againstBig;

  const quorum_met =
    voter_count >= TALLY.QUORUM_VOTERS && winningSide >= quorumWeight && total > 0n;

  let passed = false;
  if (quorum_met) {
    // supermajority of (for+against) must be FOR; ties and below-threshold fail.
    const shareBps = (forBig * BPS) / total;
    passed = forBig > againstBig && shareBps >= BigInt(TALLY.SUPERMAJORITY_BPS);
  }

  return {
    tally_for: Amount.fromBig(forBig),
    tally_against: Amount.fromBig(againstBig),
    voter_count,
    quorum_met,
    passed,
    decision: passed ? (proposal.action || DECISION.DENY) : null,
  };
}

/**
 * Deterministic, network-free evidence judgement used when no validator.js adapter
 * is injected (graceful degrade). An argument is "supported" iff it cites at least
 * one source with a resolvable url; sourceTrust is the max declared source trust.
 * @param {import("./types.js").Argument} arg
 */
async function deterministicEvidence(arg) {
  const sources = Array.isArray(arg.sources) ? arg.sources : [];
  let maxTrust = 0;
  let hasUrl = false;
  for (const s of sources) {
    if (s && typeof s.url === "string" && /^https?:\/\/\S+/.test(s.url)) {
      hasUrl = true;
      maxTrust = Math.max(maxTrust, s.trust | 0);
    }
  }
  return { supported: hasUrl, sourceTrust: maxTrust, confidence: hasUrl ? 50 : 0 };
}

// ---------------------------------------------------------------------------
// Verdict finalization
// ---------------------------------------------------------------------------

/**
 * Tally a CLOSED proposal and emit a signed `Verdict`. Requires the chain to be
 * past the proposal's close_height. Sets `decision` to the tallied outcome:
 * the proposal's action ('allow'|'deny') when it PASSES, else the inverse (the
 * status-quo / "do not enact" outcome). `policy_id` is left undefined here — it is
 * filled by policy.js when the Verdict is enacted into a Policy.
 *
 * @param {import("./ce.js").CeClient} ce
 * @param {import("./types.js").PolicyProposal} proposal
 * @param {import("./types.js").Vote[]} votes
 * @param {import("./types.js").Argument[]} args
 * @param {(payload:string)=>Promise<string>} signer
 * @param {Object} [opts]  forwarded to tally(); plus opts.currentHeight (else from ce.status)
 * @returns {Promise<import("./types.js").Verdict>}
 */
export async function finalizeVerdict(ce, proposal, votes, args, signer, opts = {}) {
  if (!proposal || !proposal.id) throw new TypeError("finalizeVerdict: proposal.id required");

  let currentHeight = opts.currentHeight;
  if (currentHeight === undefined) {
    const st = await ce.status();
    currentHeight = (st && st.height) | 0;
  }
  if (!(currentHeight > (proposal.close_height | 0))) {
    throw new Error(
      `finalizeVerdict: proposal still open (height ${currentHeight} <= close ${proposal.close_height})`,
    );
  }

  const t = await tally(ce, proposal, votes, args, opts);

  // Beacon at finalization for auditability.
  let beacon_height = 0;
  let beacon_hash = "0".repeat(64);
  try {
    const b = await ce.beacon();
    beacon_height = (b && b.height) | 0;
    beacon_hash = (b && b.hash) || beacon_hash;
  } catch {
    /* beacon best-effort; verdict still auditable via tallies */
  }

  // decision: PASS => enact the proposed action; FAIL => the opposite (status quo).
  const proposed = proposal.action || DECISION.DENY;
  const opposite = proposed === DECISION.DENY ? DECISION.ALLOW : DECISION.DENY;
  const decision = t.passed ? proposed : opposite;

  const verdict = makeVerdict({
    proposal_id: proposal.id,
    decision,
    tally_for: t.tally_for,
    tally_against: t.tally_against,
    voter_count: t.voter_count,
    // policy_id intentionally omitted (policy.js sets it on enactment).
    beacon_height,
    beacon_hash,
    state: STATE.CLOSED,
    author: opts.author ?? proposal.author,
    ts: opts.ts,
  });

  const finalized = await finalize(verdict, signer);
  try {
    const bytes = new TextEncoder().encode(JSON.stringify(finalized));
    const cid = await ce.putBlob(bytes);
    await announceArtifact(ce, { type: EV.VERDICT, id: finalized.id, cid, height: beacon_height });
  } catch {
    /* persistence + announce best-effort */
  }
  return finalized;
}

// ---------------------------------------------------------------------------
// Self-test (no network) — run with: node src/voting.js  OR  import __selftest
// ---------------------------------------------------------------------------

/**
 * Offline self-test. Builds an in-memory CeClient stub and exercises isqrt,
 * quadWeight monotonicity + whale damping, dedup, the argument fold, quorum,
 * supermajority, and verdict gating. Throws on the first failed assertion.
 * @returns {Promise<{ok:true, checks:number}>}
 */
export async function __selftest() {
  let checks = 0;
  const assert = (cond, msg) => {
    checks++;
    if (!cond) throw new Error(`selftest: ${msg}`);
  };

  // --- isqrt ---
  assert(isqrt(0n) === 0n, "isqrt(0)");
  assert(isqrt(1n) === 1n, "isqrt(1)");
  assert(isqrt(15n) === 3n, "isqrt(15)=3");
  assert(isqrt(16n) === 4n, "isqrt(16)=4");
  assert(isqrt(10n ** 18n) === 10n ** 9n, "isqrt(1e18)=1e9");

  // --- quadWeight: monotone + whale damping ---
  const big = Amount.fromCredits("100"); // 100 credits raw
  const small = Amount.fromCredits("1"); // 1 credit raw
  const qBig = Amount.toBig(quadWeight(big));
  const qSmall = Amount.toBig(quadWeight(small));
  assert(qBig > qSmall, "quad monotone");
  // raw ratio 100x -> damped ratio should be ~10x, definitely < 100x.
  assert(qBig < qSmall * 100n, "quad damps whales");
  assert(qBig >= qSmall * 9n && qBig <= qSmall * 11n, "quad ~sqrt(100)=10x");
  assert(quadWeight("0") === "0", "quad(0)=0");

  // --- dedupe: last-write-wins per (author,target) ---
  const pid = "a".repeat(64);
  const mk = (author, dir, ts, id, argument_id) => ({
    kind: "vote",
    proposal_id: pid,
    argument_id,
    direction: dir,
    weight: Amount.fromCredits("1"),
    beacon_height: 0,
    beacon_hash: "0".repeat(64),
    ts,
    author,
    id,
  });
  const A = "b".repeat(64);
  const deduped = dedupeVotes(
    [mk(A, "up", 1, "1".repeat(64)), mk(A, "down", 2, "2".repeat(64))],
    pid,
  );
  assert(deduped.length === 1 && deduped[0].direction === "down", "dedupe last-write-wins");

  // --- tally: passing case with quorum + supermajority + a supporting proof ---
  const ceStub = {
    async beacon() { return { height: 10, hash: "f".repeat(64) }; },
    async status() { return { height: 999 }; },
    async putBlob() { return "00".repeat(32); },
  };
  const voter = (n) => String(n).repeat(64).slice(0, 64);
  const proposal = {
    kind: "proposal",
    title: "ban x",
    statement: "ban x",
    category: "x",
    action: DECISION.DENY,
    expertise_tags: [],
    open_height: 0,
    close_height: 100,
    state: STATE.OPEN,
    ts: 1,
    author: voter("9"),
    id: pid,
  };
  // 4 FOR voters (>= quorum 3) of 1 credit raw each, 1 AGAINST.
  const votes = [
    mk(voter("1"), "up", 5, "a1".padEnd(64, "0")),
    mk(voter("2"), "up", 5, "a2".padEnd(64, "0")),
    mk(voter("3"), "up", 5, "a3".padEnd(64, "0")),
    mk(voter("4"), "up", 5, "a4".padEnd(64, "0")),
    mk(voter("5"), "down", 5, "a5".padEnd(64, "0")),
  ];
  const argId = "c".repeat(64);
  const proofArg = {
    kind: "argument",
    proposal_id: pid,
    arg_kind: ARG_KIND.PROOF,
    body: "evidence",
    sources: [{ url: "https://example.org/study", title: "Study", trust: 90 }],
    ts: 2,
    author: voter("6"),
    id: argId,
  };
  // a couple of upvotes on the proof argument
  const argVotes = [
    mk(voter("1"), "up", 6, "d1".padEnd(64, "0"), argId),
    mk(voter("2"), "up", 6, "d2".padEnd(64, "0"), argId),
  ];

  const res = await tally(
    ceStub,
    proposal,
    [...votes, ...argVotes],
    [proofArg],
    { allowUnsigned: true },
  );
  assert(res.voter_count >= 3, "quorum voter count");
  assert(res.quorum_met === true, "quorum met");
  assert(res.passed === true, "supermajority passes");
  assert(res.decision === DECISION.DENY, "decision = proposed action on pass");
  assert(Amount.toBig(res.tally_for) > Amount.toBig(res.tally_against), "for > against");

  // --- tally: below quorum fails ---
  const tooFew = await tally(
    ceStub,
    proposal,
    [mk(voter("1"), "up", 5, "e1".padEnd(64, "0")), mk(voter("2"), "up", 5, "e2".padEnd(64, "0"))],
    [],
    { allowUnsigned: true },
  );
  assert(tooFew.quorum_met === false, "below quorum");
  assert(tooFew.passed === false && tooFew.decision === null, "below quorum fails");

  // --- tally: tie fails (status quo) ---
  const tie = await tally(
    ceStub,
    proposal,
    [
      mk(voter("1"), "up", 5, "f1".padEnd(64, "0")),
      mk(voter("2"), "down", 5, "f2".padEnd(64, "0")),
      mk(voter("3"), "up", 5, "f3".padEnd(64, "0")),
      mk(voter("4"), "down", 5, "f4".padEnd(64, "0")),
    ],
    [],
    { allowUnsigned: true },
  );
  assert(tie.passed === false, "tie fails");

  // --- argument with no verified source does NOT count ---
  const badArg = { ...proofArg, id: "9".repeat(64), sources: [{ url: "not-a-url", title: "", trust: 5 }] };
  const noEvidence = await tally(
    ceStub,
    proposal,
    [
      mk(voter("1"), "up", 6, "g1".padEnd(64, "0"), "9".repeat(64)),
      mk(voter("2"), "up", 6, "g2".padEnd(64, "0"), "9".repeat(64)),
    ],
    [badArg],
    { allowUnsigned: true },
  );
  // only the (zero) direct votes => no for-weight from the argument
  assert(Amount.isZero(noEvidence.tally_for), "unverified argument contributes nothing");

  // --- verdict gating: still-open proposal throws ---
  let threw = false;
  try {
    await finalizeVerdict(ceStub, proposal, votes, [proofArg], undefined, { currentHeight: 50 });
  } catch {
    threw = true;
  }
  assert(threw, "finalizeVerdict throws while open");

  // --- verdict: closed + passing => decision = proposed action, content-addressed ---
  const verdict = await finalizeVerdict(
    ceStub,
    proposal,
    [...votes, ...argVotes],
    [proofArg],
    undefined,
    { currentHeight: 101, allowUnsigned: true, ts: 123 },
  );
  assert(verdict.kind === "verdict" && verdict.id && verdict.id.length === 64, "verdict finalized");
  assert(verdict.decision === DECISION.DENY, "verdict decision on pass");
  assert(verdict.proposal_id === pid, "verdict links proposal");
  // recompute id to prove content-addressing
  assert((await artifactId(verdict)) === verdict.id, "verdict id is content-addressed");

  return { ok: true, checks };
}

// Run the self-test when executed directly (node src/voting.js).
if (
  typeof process !== "undefined" &&
  process.argv &&
  import.meta.url === `file://${process.argv[1]}`
) {
  __selftest()
    .then((r) => {
      console.log(`voting.js selftest OK (${r.checks} checks)`);
    })
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
