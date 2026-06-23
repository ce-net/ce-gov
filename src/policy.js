// @ce-net/gov — active policy resolution + Guardian export.
//
// This module is the SINGLE SOURCE OF TRUTH for "what is currently banned/allowed".
// Both the pre-run scan (src/scan.js) and the runtime monitor (src/monitor.js) read the
// active policy set from here; never from raw blobs/signals directly.
//
// What it does
// ------------
//   * `enactFromVerdict(ce, verdict, proposal, signer)` — turn a PASSING governance Verdict
//     (the output of src/voting.js) into a signed, content-addressed `Policy` artifact, persist
//     it as a blob, and broadcast it as a CEP-1 signal.
//   * `activePolicySet(ce, opts)` — read all enacted Policy artifacts (and the Verdicts that
//     authored them), fold them into the CURRENT set (last-writer-per-category wins, superseded
//     dropped), and compute a deterministic `policy_set_id = hashHex(canonical(sorted policies))`.
//     That id is the `policy_set_id` referenced by every ScanRequest/ScanVerdict/AbuseReport, so a
//     policy change deterministically invalidates stale scan verdicts (Guardian cache rule).
//   * `guardPolicyExport(policySet)` — render the enacted `deny` categories into the
//     `GuardPolicy.banned_categories` shape (guardian.md §5) the node Guardian reads. A candidate
//     only — adoption is per-operator opt-in (no global ban oracle).
//   * `categoryDecision(policySet, category)` — resolve a single category to 'allow'|'deny'|null.
//
// Plus two convenience wrappers the scan/monitor app layer uses:
//   * `getActivePolicy(ce, opts)` — alias of `activePolicySet`.
//   * `subscribe(ce, cb, opts)` — watch CEP-1 signals and re-resolve the active set, calling
//     `cb(policySet)` whenever it CHANGES (id differs). Returns `{ close() }`.
//
// DESIGN RULES:
//   * No IO except through the passed-in `CeClient`. Pure functions where possible.
//   * Money is never touched here (policies are categorical). Scores/ids are strings.
//   * Build artifacts with the `make*` factory, then `finalize(artifact, signer)`.
//   * `signer: (payloadString) => Promise<128-hex>` is injected by the caller; never created here.

import {
  makePolicy,
  finalize,
  hashHex,
  canonical,
  DECISION,
  STATE,
  KIND,
  isValid,
  PolicySchema,
  artifactId,
  fromHex,
} from "./types.js";

// ---------------------------------------------------------------------------
// Defaults — the seed banned categories (guardian.md §5: defaults ON, overridable).
// These are app-tier defaults only; the node still enforces only its operator's adopted policy.
// ---------------------------------------------------------------------------

/** @type {readonly string[]} */
export const DEFAULT_BANNED_CATEGORIES = Object.freeze([
  "cryptomining",
  "ddos",
  "port_scan",
  "spam",
  "malware",
]);

// ---------------------------------------------------------------------------
// JSDoc types
// ---------------------------------------------------------------------------

/**
 * @typedef {import('./types.js').Policy} Policy
 * @typedef {import('./types.js').Verdict} Verdict
 * @typedef {import('./types.js').PolicyProposal} PolicyProposal
 */

/**
 * @typedef {Object} ActivePolicySet
 * @property {string} id              policy_set_id = hashHex(canonical(sorted policy snapshots))
 * @property {Policy[]} policies      the resolved, deduped, enacted policies (sorted by category)
 * @property {number} at_height       the height at which this set was resolved (provenance)
 */

/**
 * @typedef {Object} GuardPolicyExport
 * @property {string[]} banned_categories  enacted 'deny' categories (sorted, deduped)
 * @property {string[]} allow              enacted 'allow' categories (explicit permits; sorted)
 * @property {string} generated_from       the policy_set_id this export was derived from
 */

// ---------------------------------------------------------------------------
// enactFromVerdict — Verdict (passing) -> signed Policy
// ---------------------------------------------------------------------------

/**
 * Build a `Policy` from a passing `Verdict` + its `PolicyProposal`, finalize it (content id + sig),
 * persist it as a blob, and broadcast it as a CEP-1 signal.
 *
 * The proposal supplies the category/action/title vocabulary; the verdict supplies authority
 * (`verdict_id`) and must reference the same proposal. The verdict's `decision` is the action.
 *
 * @param {import('./ce.js').CeClient} ce
 * @param {Verdict} verdict     a finalized Verdict (must have an `id`); decision allow|deny
 * @param {PolicyProposal} proposal  the proposal the verdict resolved (supplies category/action)
 * @param {(payload: string) => Promise<string>} [signer]
 * @returns {Promise<Policy>}
 */
export async function enactFromVerdict(ce, verdict, proposal, signer) {
  if (!verdict || verdict.kind !== KIND.VERDICT) {
    throw new TypeError("enactFromVerdict: verdict must be a Verdict artifact");
  }
  if (!verdict.id) {
    throw new TypeError("enactFromVerdict: verdict must be finalized (missing id)");
  }
  if (!proposal || proposal.kind !== KIND.PROPOSAL) {
    throw new TypeError("enactFromVerdict: proposal must be a PolicyProposal artifact");
  }
  if (verdict.proposal_id !== proposal.id) {
    throw new TypeError("enactFromVerdict: verdict.proposal_id does not match proposal.id");
  }
  // The verdict's decision IS the action this policy enforces (allow or deny).
  const action = verdict.decision === DECISION.ALLOW ? DECISION.ALLOW : DECISION.DENY;

  const policy = makePolicy({
    category: proposal.category,
    title: proposal.title || proposal.category,
    description: proposal.statement || "",
    action,
    verdict_id: verdict.id,
    state: STATE.ENACTED,
    // author of the policy is whoever finalized the verdict (the tally finalizer)
    author: verdict.author,
    ts: verdict.ts,
  });

  const finalized = await finalize(policy, signer);

  // Persist + broadcast. The blob is the content-addressed source of truth; the signal announces it.
  const bytes = new TextEncoder().encode(JSON.stringify(finalized));
  await ce.putBlob(bytes);

  return finalized;
}

// ---------------------------------------------------------------------------
// activePolicySet — fold enacted Policies into the current set
// ---------------------------------------------------------------------------

/**
 * Resolve the CURRENT active policy set from all known enacted Policy artifacts.
 *
 * Resolution rules (deterministic):
 *   1. Collect every valid, enacted `Policy` artifact from signals/blobs.
 *   2. Drop policies whose `state` is `superseded`.
 *   3. Dedup per `category`: the LATEST writer wins (higher `ts`, then lexicographically larger
 *      `id` as a stable tiebreak). This makes a later passing verdict for a category override an
 *      earlier one without needing a global clock.
 *   4. Sort the survivors by category for a stable canonical form.
 *   5. `policy_set_id = hashHex(canonical(<category,action,verdict_id snapshots sorted>))`.
 *
 * The id intentionally folds ONLY the load-bearing fields (category, action, verdict_id) so that
 * cosmetic edits (title/description) do not churn the cache, but any rule change does.
 *
 * @param {import('./ce.js').CeClient} ce
 * @param {Object} [opts]
 * @param {Policy[]} [opts.policies]   pre-collected policies (skip the network scan; for tests)
 * @param {number} [opts.atHeight]     override the provenance height (default ce.status().height)
 * @returns {Promise<ActivePolicySet>}
 */
export async function activePolicySet(ce, opts = {}) {
  const collected = opts.policies ? opts.policies.slice() : await collectPolicies(ce);

  const resolved = resolvePolicies(collected);

  let atHeight = opts.atHeight | 0;
  if (!opts.atHeight && ce && typeof ce.status === "function") {
    try {
      const s = await ce.status();
      atHeight = Number(s && s.height) || 0;
    } catch {
      atHeight = 0;
    }
  }

  const id = await policySetId(resolved);
  return { id, policies: resolved, at_height: atHeight };
}

/** Alias kept for the scan/monitor call sites (task purpose: `getActivePolicy()`). */
export async function getActivePolicy(ce, opts = {}) {
  return activePolicySet(ce, opts);
}

/**
 * Pure folding step: dedup per category (last writer wins) and drop superseded.
 * Exposed for testability; takes plain Policy objects.
 * @param {Policy[]} policies
 * @returns {Policy[]} sorted by category
 */
export function resolvePolicies(policies) {
  /** @type {Map<string, Policy>} */
  const byCat = new Map();
  for (const p of policies) {
    if (!p || p.kind !== KIND.POLICY) continue;
    if (!isValid(p, PolicySchema)) continue;
    if (p.state === STATE.SUPERSEDED) continue;
    const prev = byCat.get(p.category);
    if (!prev || isNewer(p, prev)) byCat.set(p.category, p);
  }
  return [...byCat.values()].sort((a, b) => (a.category < b.category ? -1 : a.category > b.category ? 1 : 0));
}

/** Last-writer-wins comparator: newer ts wins; tie broken by larger id (stable, content-derived). */
function isNewer(a, b) {
  if ((a.ts | 0) !== (b.ts | 0)) return (a.ts | 0) > (b.ts | 0);
  const ai = a.id || "";
  const bi = b.id || "";
  return ai > bi;
}

/**
 * Compute the deterministic policy_set_id over the resolved set.
 * Folds only the rule-bearing fields so cosmetic edits don't invalidate scan caches.
 * @param {Policy[]} resolved   already sorted by category
 * @returns {Promise<string>} 64-hex
 */
export async function policySetId(resolved) {
  const snapshot = resolved.map((p) => ({
    category: p.category,
    action: p.action,
    verdict_id: p.verdict_id || "",
  }));
  return hashHex(snapshot);
}

// ---------------------------------------------------------------------------
// Collection — read enacted Policy artifacts from signals (and back them with blobs)
// ---------------------------------------------------------------------------

/**
 * Best-effort collection of enacted Policy artifacts from the CEP-1 signal window.
 * Policies are broadcast as JSON-payload signals at enact time (see enactFromVerdict ->
 * the blob store, which for `signalBlobStore` IS a signal). We decode each signal payload, keep
 * the ones that parse as a valid enacted Policy. Bounded by the node's 100-signal window; the app
 * layer may also seed `opts.policies` from a durable index.
 * @param {import('./ce.js').CeClient} ce
 * @returns {Promise<Policy[]>}
 */
export async function collectPolicies(ce) {
  /** @type {Policy[]} */
  const out = [];
  if (!ce || typeof ce.signals !== "function") return out;
  let list;
  try {
    list = await ce.signals();
  } catch {
    return out;
  }
  for (const s of Array.isArray(list) ? list : []) {
    const obj = decodeSignalPolicy(s);
    if (obj && obj.kind === KIND.POLICY && obj.state === STATE.ENACTED && isValid(obj, PolicySchema)) {
      out.push(obj);
    }
  }
  return out;
}

/** Try to extract a Policy JSON object from a CEP-1 signal's hex payload. Returns null on miss. */
function decodeSignalPolicy(signal) {
  if (!signal || typeof signal.payload_hex !== "string" || signal.payload_hex.length === 0) return null;
  let text;
  try {
    text = new TextDecoder().decode(fromHex(signal.payload_hex));
  } catch {
    return null;
  }
  try {
    const obj = JSON.parse(text);
    return obj && typeof obj === "object" ? obj : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Guardian export + single-category resolution
// ---------------------------------------------------------------------------

/**
 * Map an active policy set into the node Guardian's `GuardPolicy.banned_categories` shape
 * (guardian.md §5). Produces a CANDIDATE — adoption is per-operator opt-in; this is not a
 * network-wide oracle. The node still enforces only the operator's adopted policy.
 *
 * @param {ActivePolicySet} policySet
 * @returns {GuardPolicyExport}
 */
export function guardPolicyExport(policySet) {
  const policies = (policySet && policySet.policies) || [];
  const banned = new Set();
  const allow = new Set();
  for (const p of policies) {
    if (!p || p.kind !== KIND.POLICY) continue;
    if (p.action === DECISION.DENY) banned.add(p.category);
    else if (p.action === DECISION.ALLOW) allow.add(p.category);
  }
  return {
    banned_categories: [...banned].sort(),
    allow: [...allow].sort(),
    generated_from: (policySet && policySet.id) || "",
  };
}

/**
 * Resolve a single category against the active set.
 * @param {ActivePolicySet} policySet
 * @param {string} category
 * @returns {'allow'|'deny'|null}  null when the category is not governed by the set
 */
export function categoryDecision(policySet, category) {
  const policies = (policySet && policySet.policies) || [];
  for (const p of policies) {
    if (p && p.kind === KIND.POLICY && p.category === category) {
      return p.action === DECISION.ALLOW ? DECISION.ALLOW : DECISION.DENY;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// subscribe — watch for policy-set changes
// ---------------------------------------------------------------------------

/**
 * Watch CEP-1 signals and re-resolve the active set; invoke `cb(policySet)` whenever the
 * `policy_set_id` CHANGES (deduped). Fires once immediately with the current set, then on changes.
 * Returns an `{ close() }` handle. No-op closer if the node has no stream.
 *
 * @param {import('./ce.js').CeClient} ce
 * @param {(policySet: ActivePolicySet) => void} cb
 * @param {Object} [opts]
 * @param {(err: Error) => void} [opts.onErr]
 * @returns {{ close(): void }}
 */
export function subscribe(ce, cb, opts = {}) {
  let lastId = null;
  let closed = false;

  const refresh = async () => {
    if (closed) return;
    try {
      const set = await activePolicySet(ce);
      if (set.id !== lastId) {
        lastId = set.id;
        cb(set);
      }
    } catch (err) {
      if (opts.onErr) opts.onErr(err);
    }
  };

  // initial resolve
  refresh();

  // any new signal MIGHT be a policy enactment; cheap to re-resolve (bounded window).
  let handle = { close() {} };
  if (ce && typeof ce.signalsStream === "function") {
    handle = ce.signalsStream(() => { refresh(); }, opts.onErr);
  }

  return {
    close() {
      closed = true;
      try { handle.close(); } catch { /* ignore */ }
    },
  };
}

// ---------------------------------------------------------------------------
// Self-test (no network) — run with: node src/policy.js
// ---------------------------------------------------------------------------

/**
 * In-process self-test. Returns the number of assertions that passed; throws on failure.
 * Exercises folding, deterministic id, Guardian export, category resolution, and enactFromVerdict
 * against an in-memory blob store — no network.
 * @returns {Promise<number>}
 */
export async function __selftest() {
  let n = 0;
  const assert = (c, m) => { if (!c) throw new Error("selftest: " + m); n++; };

  const AUTHOR = "a".repeat(64);
  const VID1 = "1".repeat(64);
  const VID2 = "2".repeat(64);

  // Build three policies: deny cryptomining (old), deny cryptomining (new, supersedes by ts),
  // allow fuzzing.
  const pOld = await finalize(makePolicy({
    category: "cryptomining", action: DECISION.DENY, verdict_id: VID1, author: AUTHOR, ts: 1000,
    state: STATE.ENACTED, title: "ban miners",
  }));
  const pNew = await finalize(makePolicy({
    category: "cryptomining", action: DECISION.DENY, verdict_id: VID2, author: AUTHOR, ts: 2000,
    state: STATE.ENACTED, title: "ban miners v2",
  }));
  const pAllow = await finalize(makePolicy({
    category: "fuzzing", action: DECISION.ALLOW, verdict_id: VID1, author: AUTHOR, ts: 1500,
    state: STATE.ENACTED, title: "permit fuzzers",
  }));
  const pSuperseded = await finalize(makePolicy({
    category: "spam", action: DECISION.DENY, verdict_id: VID1, author: AUTHOR, ts: 1200,
    state: STATE.SUPERSEDED, title: "old spam rule",
  }));

  // resolvePolicies: cryptomining keeps the NEWER (pNew); spam (superseded) dropped; fuzzing kept.
  const resolved = resolvePolicies([pOld, pNew, pAllow, pSuperseded]);
  assert(resolved.length === 2, "expected 2 resolved policies");
  const crypto = resolved.find((p) => p.category === "cryptomining");
  assert(crypto && crypto.verdict_id === VID2, "newer cryptomining policy should win");
  assert(!resolved.some((p) => p.category === "spam"), "superseded spam dropped");
  // sorted by category: cryptomining < fuzzing
  assert(resolved[0].category === "cryptomining" && resolved[1].category === "fuzzing", "sorted by category");

  // policySetId is deterministic and order-independent of input.
  const id1 = await policySetId(resolved);
  const resolved2 = resolvePolicies([pAllow, pSuperseded, pNew, pOld]);
  const id2 = await policySetId(resolved2);
  assert(id1 === id2, "policy_set_id must be input-order independent");
  assert(/^[0-9a-f]{64}$/.test(id1), "policy_set_id is 64-hex");

  // A rule change (different action) must change the id.
  const flipped = resolved.map((p) => p.category === "fuzzing" ? { ...p, action: DECISION.DENY } : p);
  const id3 = await policySetId(flipped);
  assert(id3 !== id1, "rule change must change policy_set_id");

  // activePolicySet via injected policies (no network).
  const set = await activePolicySet({ status: async () => ({ height: 42 }) }, { policies: [pOld, pNew, pAllow] });
  assert(set.at_height === 42, "at_height carried from status");
  assert(set.id === id1, "activePolicySet id matches policySetId");
  assert(set.policies.length === 2, "activePolicySet folded to 2");

  // guardPolicyExport
  const exp = guardPolicyExport(set);
  assert(exp.banned_categories.length === 1 && exp.banned_categories[0] === "cryptomining", "one banned category");
  assert(exp.allow.length === 1 && exp.allow[0] === "fuzzing", "one allow category");
  assert(exp.generated_from === set.id, "export bound to policy_set_id");

  // categoryDecision
  assert(categoryDecision(set, "cryptomining") === DECISION.DENY, "cryptomining -> deny");
  assert(categoryDecision(set, "fuzzing") === DECISION.ALLOW, "fuzzing -> allow");
  assert(categoryDecision(set, "unknown_cat") === null, "ungoverned -> null");

  // collectPolicies decodes a signal payload (enacted policy round-trips through a signal).
  const payloadHex = bytesToHex(new TextEncoder().encode(JSON.stringify(pNew)));
  const collected = await collectPolicies({
    signals: async () => [{ payload_hex: payloadHex }, { payload_hex: "" }, {}],
  });
  assert(collected.length === 1 && collected[0].verdict_id === VID2, "collectPolicies decoded one policy");

  // enactFromVerdict: a passing verdict + matching proposal -> enacted Policy persisted as a blob.
  const blobs = new Map();
  const fakeCe = {
    async putBlob(bytes) { const k = await sha(bytes); blobs.set(k, bytes); return k; },
    async getBlob(k) { return blobs.get(k) || null; },
  };
  const PROP_ID = "f".repeat(64);
  const proposal = {
    kind: KIND.PROPOSAL, id: PROP_ID, category: "ddos", title: "ban ddos",
    statement: "ban hosting of ddos tooling", author: AUTHOR,
  };
  const verdict = {
    kind: KIND.VERDICT, id: VID1, proposal_id: PROP_ID, decision: DECISION.DENY,
    author: AUTHOR, ts: 3000,
  };
  const enacted = await enactFromVerdict(fakeCe, verdict, proposal);
  assert(enacted.kind === KIND.POLICY && enacted.category === "ddos", "enacted policy category");
  assert(enacted.action === DECISION.DENY, "enacted action deny");
  assert(enacted.verdict_id === VID1, "enacted policy carries verdict_id");
  assert(enacted.state === STATE.ENACTED, "enacted state");
  assert(!!enacted.id, "enacted policy finalized with id");
  assert(blobs.size === 1, "enacted policy persisted as a blob");

  // recompute id of enacted policy matches finalize() output (content-addressing intact).
  const recomputed = await artifactId(enacted);
  assert(recomputed === enacted.id, "enacted policy id is content-addressed");

  // mismatched verdict/proposal rejected.
  let threw = false;
  try {
    await enactFromVerdict(fakeCe, { ...verdict, proposal_id: "0".repeat(64) }, proposal);
  } catch { threw = true; }
  assert(threw, "mismatched verdict/proposal rejected");

  return n;
}

// tiny local hex/sha helpers for the self-test (no import cycle, no network)
function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
async function sha(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
  return bytesToHex(new Uint8Array(d));
}

// Run the self-test when executed directly (node src/policy.js).
if (
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1] &&
  import.meta.url === `file://${process.argv[1]}`
) {
  __selftest()
    .then((n) => { console.log(`policy.js selftest OK (${n} assertions)`); })
    .catch((e) => { console.error(e); process.exit(1); });
}
