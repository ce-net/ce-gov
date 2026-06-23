// @ce-net/gov — (c) proposals + arguments.
//
// Proposal lifecycle: create / list / get policy proposals (e.g. "ban pornographic
// hosting") and the arguments (proof / antiproof) attached to them.
//
// Persistence model (forward-compatible, zero-dep):
//   * Every artifact is content-addressed (its `id` == sha256 over its signing payload,
//     computed by `finalize` in types.js).
//   * The artifact JSON bytes are stored as a blob via `ce.putBlob` (the pluggable blob
//     store in ce.js — in-memory or signal-backed).
//   * A discovery index is announced over CEP-1 signals: at create time we broadcast a
//     small JSON index entry as a signal payload so other nodes can enumerate proposals
//     and arguments by scanning `GET /signals`.
//
// This module OWNS reading/writing proposal + argument artifacts only. It NEVER tallies
// votes (that is voting.js) and NEVER mutates host resources. State transitions
// (open -> closed -> enacted/superseded) are advisory metadata stamped onto artifacts;
// the authoritative outcome lives in the Verdict (voting.js) and the active policy set
// (policy.js). `isOpen` derives open/closed purely from heights so callers don't trust a
// stale `state` string.
//
// All cross-module communication is via the typed artifacts from types.js — no module
// imports another's internals. The only IO is through the injected `CeClient`.

import {
  KIND,
  STATE,
  ARG_KIND,
  GOV_DOMAIN,
  SCHEMA_BY_KIND,
  PolicyProposalSchema,
  ArgumentSchema,
  makeProposal,
  makeArgument,
  makeSource,
  finalize,
  validate,
  isValid,
  artifactId,
  canonical,
} from "./types.js";

/**
 * @typedef {import("./types.js").PolicyProposal} PolicyProposal
 * @typedef {import("./types.js").Argument} Argument
 * @typedef {import("./types.js").Source} Source
 * @typedef {import("./ce.js").CeClient} CeClient
 */

// A small magic prefix on the index-signal payload so we can recognize governance
// discovery entries among arbitrary CEP-1 signal traffic. The payload itself stays
// purely advisory (the blob is the source of truth, fetched + re-validated).
const INDEX_TAG = "ce-gov-index-v1";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** @param {object} obj @returns {Uint8Array} */
function jsonBytes(obj) {
  return enc.encode(canonical(obj));
}

/** Hex-encode bytes (local, to avoid an import cycle / keep this module self-contained). */
function toHexLocal(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Hex-decode (tolerant: returns null on malformed input). */
function fromHexLocal(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Build the advisory discovery-index entry for an artifact and broadcast it as a CEP-1
 * signal. Best-effort: if the broadcast fails we still return (the blob is authoritative).
 * @param {CeClient} ce
 * @param {{kind:string,id:string,proposal_id?:string,cid:string}} entry
 */
async function announceIndex(ce, entry) {
  const payload = { tag: INDEX_TAG, ...entry };
  const bytes = jsonBytes(payload);
  try {
    await ce.signalsSend({ payload_hex: toHexLocal(bytes), to: "broadcast" });
  } catch {
    // Discovery is best-effort; the artifact is already stored as a blob.
  }
}

/**
 * Parse a CEP-1 signal's payload as a governance discovery-index entry, or null.
 * @param {object} signal
 * @returns {null | {tag:string,kind:string,id:string,proposal_id?:string,cid:string}}
 */
function parseIndexSignal(signal) {
  const hex = signal && signal.payload_hex;
  if (!hex) return null;
  const bytes = fromHexLocal(hex);
  if (!bytes) return null;
  let obj;
  try {
    obj = JSON.parse(dec.decode(bytes));
  } catch {
    return null;
  }
  if (!obj || obj.tag !== INDEX_TAG || typeof obj.cid !== "string" || typeof obj.kind !== "string") {
    return null;
  }
  return obj;
}

/**
 * Store an artifact as a blob and return its content id (cid). The cid is the sha256 of
 * the canonical JSON bytes (what the blob store hashes). It is NOT the same as the
 * artifact `id` (which is sha256 of the domain-tagged signing payload), so we keep both.
 * @param {CeClient} ce
 * @param {object} artifact  a finalized (has `id`) artifact
 * @returns {Promise<string>} cid
 */
async function storeArtifact(ce, artifact) {
  return ce.putBlob(jsonBytes(artifact));
}

/**
 * Load and parse a stored artifact blob by cid, validating it against its schema.
 * @param {CeClient} ce
 * @param {string} cid
 * @param {string} [expectKind]  if set, require artifact.kind === expectKind
 * @returns {Promise<object|null>}
 */
async function loadArtifactByCid(ce, cid, expectKind) {
  const bytes = await ce.getBlob(cid);
  if (!bytes) return null;
  let obj;
  try {
    obj = JSON.parse(dec.decode(bytes));
  } catch {
    return null;
  }
  if (!obj || typeof obj.kind !== "string") return null;
  if (expectKind && obj.kind !== expectKind) return null;
  const schema = SCHEMA_BY_KIND[obj.kind];
  if (!schema || !isValid(obj, schema)) return null;
  return obj;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a policy proposal: build, finalize (content-address + sign), persist as a blob,
 * and announce it over a CEP-1 discovery signal.
 *
 * `fields.open_height` defaults to the current chain height (from `ce.status()`); if it
 * cannot be read it defaults to 0. `fields.close_height` defaults to open_height + a
 * sane voting window if not supplied.
 *
 * @param {CeClient} ce
 * @param {Partial<PolicyProposal>} fields
 * @param {(payload: string) => Promise<string>} signer
 * @returns {Promise<PolicyProposal & {id:string, sig?:string}>}
 */
export async function createProposal(ce, fields, signer) {
  if (!ce) throw new TypeError("createProposal: ce client required");

  let openHeight = fields.open_height;
  if (openHeight === undefined || openHeight === null) {
    openHeight = await currentHeight(ce);
  }
  openHeight = openHeight | 0;

  let closeHeight = fields.close_height;
  if (closeHeight === undefined || closeHeight === null) {
    closeHeight = openHeight + DEFAULT_VOTING_WINDOW_BLOCKS;
  }
  closeHeight = closeHeight | 0;

  const proposal = makeProposal({
    ...fields,
    state: STATE.OPEN,
    open_height: openHeight,
    close_height: closeHeight,
  });

  const finalized = await finalize(proposal, signer);
  // Defensive: ensure the finalized artifact still validates as a proposal.
  validate(finalized, PolicyProposalSchema, "proposal");

  const cid = await storeArtifact(ce, finalized);
  await announceIndex(ce, { kind: KIND.PROPOSAL, id: finalized.id, cid });
  return finalized;
}

/**
 * Attach an argument (proof / antiproof) to a proposal. Arguments MUST cite at least one
 * source to be weighted by voting.js, so we reject empty `sources` here.
 *
 * @param {CeClient} ce
 * @param {Partial<Argument>} fields
 * @param {(payload: string) => Promise<string>} signer
 * @returns {Promise<Argument & {id:string, sig?:string}>}
 */
export async function addArgument(ce, fields, signer) {
  if (!ce) throw new TypeError("addArgument: ce client required");
  if (!fields || !fields.proposal_id) throw new TypeError("addArgument: proposal_id required");
  const sources = (fields.sources || []).map(makeSource);
  if (sources.length === 0) {
    throw new TypeError("addArgument: at least one cited source is required");
  }
  if (fields.arg_kind !== ARG_KIND.PROOF && fields.arg_kind !== ARG_KIND.ANTIPROOF) {
    throw new TypeError(`addArgument: arg_kind must be one of ${Object.values(ARG_KIND).join("|")}`);
  }

  const argument = makeArgument({ ...fields, sources });
  const finalized = await finalize(argument, signer);
  validate(finalized, ArgumentSchema, "argument");

  const cid = await storeArtifact(ce, finalized);
  await announceIndex(ce, {
    kind: KIND.ARGUMENT,
    id: finalized.id,
    proposal_id: finalized.proposal_id,
    cid,
  });
  return finalized;
}

/**
 * Load a proposal by its artifact id. We resolve the id -> cid via the discovery index
 * (CEP-1 signals), then fetch + validate the blob. Also tries `id` directly as a cid, in
 * case the blob store is content-addressed by the same hash (it is not in general, but a
 * caller may pass a cid). Returns null if not found / invalid.
 *
 * @param {CeClient} ce
 * @param {string} id  artifact id (or, as a fallback, a blob cid)
 * @returns {Promise<PolicyProposal|null>}
 */
export async function loadProposal(ce, id) {
  if (!ce || typeof id !== "string") return null;
  const cid = await resolveCid(ce, id, KIND.PROPOSAL);
  if (cid) {
    const obj = await loadArtifactByCid(ce, cid, KIND.PROPOSAL);
    if (obj) return obj;
  }
  // Fallback: maybe `id` is itself a cid.
  return loadArtifactByCid(ce, id, KIND.PROPOSAL);
}

/**
 * Load all arguments attached to a proposal by scanning the discovery index for argument
 * entries whose `proposal_id` matches, then fetching + validating each blob. Results are
 * de-duplicated by argument id and sorted by timestamp (ascending).
 *
 * @param {CeClient} ce
 * @param {string} proposalId
 * @returns {Promise<Argument[]>}
 */
export async function loadArguments(ce, proposalId) {
  if (!ce || typeof proposalId !== "string") return [];
  const signals = await safeSignals(ce);
  const byCid = new Map();
  for (const s of signals) {
    const entry = parseIndexSignal(s);
    if (!entry || entry.kind !== KIND.ARGUMENT) continue;
    if (entry.proposal_id !== proposalId) continue;
    byCid.set(entry.cid, entry);
  }
  const out = [];
  const seen = new Set();
  for (const cid of byCid.keys()) {
    const arg = await loadArtifactByCid(ce, cid, KIND.ARGUMENT);
    if (!arg || arg.proposal_id !== proposalId) continue;
    if (arg.id && seen.has(arg.id)) continue;
    if (arg.id) seen.add(arg.id);
    out.push(arg);
  }
  out.sort((a, b) => (a.ts | 0) - (b.ts | 0));
  return out;
}

/**
 * List proposals discovered via the CEP-1 index. Each entry is fetched + validated.
 * De-duplicated by proposal id, newest first (by ts). Optionally filter.
 *
 * @param {CeClient} ce
 * @param {Object} [opts]
 * @param {boolean} [opts.openOnly]   only proposals open at the current height
 * @param {string}  [opts.category]   exact category match
 * @param {string}  [opts.author]     exact author (64-hex) match
 * @param {number}  [opts.atHeight]   height used for openOnly (default: current height)
 * @returns {Promise<PolicyProposal[]>}
 */
export async function listProposals(ce, opts = {}) {
  if (!ce) return [];
  const signals = await safeSignals(ce);
  const cids = new Set();
  for (const s of signals) {
    const entry = parseIndexSignal(s);
    if (entry && entry.kind === KIND.PROPOSAL) cids.add(entry.cid);
  }

  const out = [];
  const seen = new Set();
  for (const cid of cids) {
    const p = await loadArtifactByCid(ce, cid, KIND.PROPOSAL);
    if (!p) continue;
    if (p.id && seen.has(p.id)) continue;
    if (p.id) seen.add(p.id);
    out.push(p);
  }

  let filtered = out;
  if (opts.category) filtered = filtered.filter((p) => p.category === opts.category);
  if (opts.author) filtered = filtered.filter((p) => p.author === opts.author);
  if (opts.openOnly) {
    const h = opts.atHeight !== undefined ? opts.atHeight | 0 : await currentHeight(ce);
    filtered = filtered.filter((p) => isOpen(p, h));
  }

  filtered.sort((a, b) => (b.ts | 0) - (a.ts | 0));
  return filtered;
}

/**
 * Is the proposal open for voting at the given height? Derived purely from the proposal's
 * open/close heights — independent of the (possibly stale) `state` string. A proposal is
 * open when open_height <= currentHeight <= close_height and it has not been superseded
 * or already enacted/closed by an authoritative verdict.
 *
 * @param {PolicyProposal} proposal
 * @param {number} currentHeight
 * @returns {boolean}
 */
export function isOpen(proposal, currentHeight) {
  if (!proposal) return false;
  const h = currentHeight | 0;
  if (proposal.state === STATE.SUPERSEDED || proposal.state === STATE.ENACTED) return false;
  const open = proposal.open_height | 0;
  const close = proposal.close_height | 0;
  return h >= open && h <= close;
}

/**
 * Compute the advisory lifecycle state of a proposal at a height, given an optional
 * authoritative verdict (from voting.js). Pure helper — does NOT mutate. State machine:
 *   no verdict + within window         -> 'open'
 *   no verdict + past close_height     -> 'closed'
 *   verdict enacted                    -> 'enacted'
 *   verdict superseded                 -> 'superseded'
 *
 * @param {PolicyProposal} proposal
 * @param {number} currentHeight
 * @param {{state?:string}} [verdict]
 * @returns {'open'|'closed'|'enacted'|'superseded'}
 */
export function lifecycleState(proposal, currentHeight, verdict) {
  if (verdict && (verdict.state === STATE.ENACTED || verdict.state === STATE.SUPERSEDED)) {
    return verdict.state;
  }
  if (proposal && proposal.state === STATE.SUPERSEDED) return STATE.SUPERSEDED;
  if (proposal && proposal.state === STATE.ENACTED) return STATE.ENACTED;
  return isOpen(proposal, currentHeight) ? STATE.OPEN : STATE.CLOSED;
}

/**
 * Verify an artifact's integrity: recompute its content id and confirm the author's
 * signature over the canonical signing payload. `verifySig` is injected (the caller wires
 * ce-cap / wallet verification): `(payload:string, sig:string, author:string) => Promise<boolean>`.
 *
 * Returns false (never throws) on any mismatch so callers can filter untrusted artifacts.
 *
 * @param {object} artifact   an artifact with id (+ optionally sig)
 * @param {(payload:string, sig:string, author:string) => (boolean|Promise<boolean>)} verifySig
 * @returns {Promise<boolean>}
 */
export async function verifyArtifact(artifact, verifySig) {
  if (!artifact || typeof artifact !== "object" || typeof artifact.kind !== "string") return false;
  const schema = SCHEMA_BY_KIND[artifact.kind];
  if (!schema || !isValid(artifact, schema)) return false;
  // Recompute the content id over the signing payload (strips id/sig internally).
  let recomputed;
  try {
    recomputed = await artifactId(artifact);
  } catch {
    return false;
  }
  if (typeof artifact.id !== "string" || artifact.id !== recomputed) return false;

  if (!artifact.sig) {
    // Content-addressed but unsigned: integrity OK, but unauthenticated. If no signature
    // verifier semantics are required, treat presence of a verifier as a hard requirement.
    return !verifySig;
  }
  if (typeof verifySig !== "function") return true; // id verified; no verifier supplied
  // Reconstruct the exact signed payload (must match what finalize signed).
  const { signingPayloadOf } = internal;
  const payload = signingPayloadOf(artifact);
  try {
    return Boolean(await verifySig(payload, artifact.sig, artifact.author));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Default voting window in blocks (~ used when close_height not supplied). */
export const DEFAULT_VOTING_WINDOW_BLOCKS = 8640; // ~1 day at 10s/block

/** Read current chain height, tolerant of missing/oddly-shaped /status. @param {CeClient} ce */
async function currentHeight(ce) {
  try {
    const st = await ce.status();
    const h = st && (st.height ?? st.tip_height ?? st.chain_height);
    return Number.isFinite(h) ? h | 0 : 0;
  } catch {
    return 0;
  }
}

/** GET /signals tolerantly (returns [] on error / non-array). @param {CeClient} ce */
async function safeSignals(ce) {
  try {
    const list = await ce.signals();
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

/**
 * Resolve an artifact id to a blob cid via the discovery index.
 * @param {CeClient} ce
 * @param {string} id
 * @param {string} kind
 * @returns {Promise<string|null>}
 */
async function resolveCid(ce, id, kind) {
  const signals = await safeSignals(ce);
  for (const s of signals) {
    const entry = parseIndexSignal(s);
    if (entry && entry.kind === kind && entry.id === id) return entry.cid;
  }
  return null;
}

// Reconstruct the exact canonical signing payload that `finalize` (types.js) signed:
//   `${GOV_DOMAIN}:${kind}:${canonical(rest without id+sig)}`
// Mirrors types.js `signingPayload` so verifyArtifact stays robust against the format.
const internal = {
  signingPayloadOf(artifact) {
    const { id, sig, ...rest } = artifact;
    return `${GOV_DOMAIN}:${artifact.kind}:${canonical(rest)}`;
  },
};

// ---------------------------------------------------------------------------
// Inline self-test (no network) — run via: node src/proposals.js --selftest
// ---------------------------------------------------------------------------

/**
 * Self-test exercising create/list/get/argument flows against the in-memory blob store +
 * a fake signal bus. No network. Returns true on success, throws on failure.
 * @returns {Promise<boolean>}
 */
export async function __selftest() {
  // Minimal fake CeClient: in-memory blob store + in-memory signal bus + fixed height.
  const blobs = new Map();
  const signals = [];
  const author = "a".repeat(64);
  // A trivial signer: deterministic 128-hex derived from payload length (test-only).
  const signer = async (payload) =>
    (payload.length.toString(16).padStart(2, "0").repeat(64)).slice(0, 128);

  const ce = {
    async status() {
      return { height: 100 };
    },
    async putBlob(bytes) {
      const cid = await sha256(bytes);
      blobs.set(cid, bytes.slice());
      return cid;
    },
    async getBlob(cid) {
      const v = blobs.get(cid);
      return v ? v.slice() : null;
    },
    async signalsSend(sig) {
      signals.push({ payload_hex: sig.payload_hex, to: sig.to });
      return { id: "x", nonce: signals.length };
    },
    async signals() {
      return signals.slice();
    },
  };

  // 1) createProposal — open_height defaults from status().height (100).
  const prop = await createProposal(
    ce,
    {
      title: "Ban pornographic hosting",
      statement: "Hosting of pornographic content is disallowed on the mesh.",
      category: "pornographic_content",
      action: "deny",
      expertise_tags: ["legal", "safety"],
      author,
    },
    signer,
  );
  assert(prop.id && prop.id.length === 64, "proposal has 64-hex id");
  assert(prop.sig && prop.sig.length === 128, "proposal signed");
  assert(prop.open_height === 100, "open_height defaulted from status height");
  assert(prop.close_height === 100 + DEFAULT_VOTING_WINDOW_BLOCKS, "close_height defaulted");
  assert(prop.state === "open", "proposal state open");

  // 2) loadProposal by id resolves via index signal.
  const loaded = await loadProposal(ce, prop.id);
  assert(loaded && loaded.id === prop.id, "loadProposal round-trips by id");
  assert(loaded.statement === prop.statement, "loaded statement matches");

  // 3) listProposals finds it; openOnly at current height keeps it.
  const all = await listProposals(ce);
  assert(all.length === 1 && all[0].id === prop.id, "listProposals lists the proposal");
  const openNow = await listProposals(ce, { openOnly: true, atHeight: 100 });
  assert(openNow.length === 1, "open at height 100");
  const openLater = await listProposals(ce, { openOnly: true, atHeight: 999999 });
  assert(openLater.length === 0, "closed past close_height");
  const byCat = await listProposals(ce, { category: "pornographic_content" });
  assert(byCat.length === 1, "category filter matches");
  const byCatMiss = await listProposals(ce, { category: "nope" });
  assert(byCatMiss.length === 0, "category filter excludes");

  // 4) addArgument requires sources; rejects when empty.
  let threw = false;
  try {
    await addArgument(ce, { proposal_id: prop.id, arg_kind: "proof", body: "x", sources: [], author }, signer);
  } catch {
    threw = true;
  }
  assert(threw, "addArgument rejects empty sources");

  const arg = await addArgument(
    ce,
    {
      proposal_id: prop.id,
      arg_kind: "proof",
      body: "Multiple jurisdictions classify this as illegal to host.",
      sources: [{ url: "https://example.org/law", title: "Statute", trust: 80 }],
      author,
    },
    signer,
  );
  assert(arg.id && arg.id.length === 64, "argument finalized");

  // 5) loadArguments finds the argument for the proposal.
  const loadedArgs = await loadArguments(ce, prop.id);
  assert(loadedArgs.length === 1 && loadedArgs[0].id === arg.id, "loadArguments round-trips");
  const otherArgs = await loadArguments(ce, "b".repeat(64));
  assert(otherArgs.length === 0, "loadArguments scoped to proposal");

  // 6) isOpen / lifecycleState pure logic.
  assert(isOpen(prop, 100) === true, "isOpen within window");
  assert(isOpen(prop, prop.close_height + 1) === false, "isOpen past close");
  assert(isOpen({ ...prop, state: "superseded" }, 100) === false, "isOpen false when superseded");
  assert(lifecycleState(prop, 100) === "open", "lifecycle open");
  assert(lifecycleState(prop, prop.close_height + 1) === "closed", "lifecycle closed");
  assert(lifecycleState(prop, 100, { state: "enacted" }) === "enacted", "lifecycle enacted via verdict");

  // 7) verifyArtifact: recompute id + verify sig via injected verifier.
  const okId = await verifyArtifact(prop, async (payload, sig) => sig === (await signer(payload)));
  assert(okId === true, "verifyArtifact accepts valid id+sig");
  const tampered = { ...prop, statement: prop.statement + "!" };
  const badId = await verifyArtifact(tampered, async () => true);
  assert(badId === false, "verifyArtifact rejects tampered (id mismatch)");
  const badSig = await verifyArtifact(prop, async () => false);
  assert(badSig === false, "verifyArtifact rejects bad signature");

  return true;
}

function assert(cond, msg) {
  if (!cond) throw new Error(`selftest failed: ${msg}`);
}

// Local sha256 for the self-test fake blob store (mirrors ce.js memoryBlobStore cid).
async function sha256(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const d = await crypto.subtle.digest("SHA-256", buf);
  let s = "";
  for (const b of new Uint8Array(d)) s += b.toString(16).padStart(2, "0");
  return s;
}

// Run the self-test when invoked directly with --selftest.
if (
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1] &&
  import.meta.url === new URL(`file://${process.argv[1]}`).href &&
  process.argv.includes("--selftest")
) {
  __selftest()
    .then(() => {
      console.log("proposals.js selftest: OK");
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
