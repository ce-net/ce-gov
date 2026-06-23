// @ce-net/gov — shared data model.
//
// This file is imported by EVERY other module. It defines:
//   - the canonical-JSON serializer and a stable SHA-256 content-hash helper
//     (Web Crypto `crypto.subtle`, available in Node >=18 and all browsers),
//   - JSDoc typedefs for the wire/persistence shapes,
//   - frozen JSON schemas (one per shape) for validation,
//   - factory functions that build a normalized, schema-valid object,
//   - the signing-payload helper every signed artifact uses.
//
// DESIGN RULES (do not violate — other modules depend on them):
//   * Money is INTEGER BASE UNITS carried as DECIMAL STRINGS. Never a JS number, never a float.
//     1 credit = 10^18 base units. Use the `Amount` helpers, never `+`/`*` on raw strings.
//   * Every persisted/broadcast artifact is CONTENT-ADDRESSED: its `id` is `hashHex(canonical(obj
//     without id+sig))`. So compute the id BEFORE signing, and sign the same canonical bytes.
//   * Canonical JSON = object keys sorted lexicographically at every depth, no insignificant
//     whitespace, UTF-8. This makes hashing and signing reproducible across implementations.
//   * Timestamps are integer Unix milliseconds (`ts`). Heights are integers.
//   * NodeIds and hashes are lowercase hex strings. Signatures are 128-hex (Ed25519, 64 bytes).
//
// Nothing here performs IO. The CE client (`ce.js`) does IO; modules combine the two.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Base units per credit (10^18), as a BigInt. */
export const CREDIT = 1_000_000_000_000_000_000n;

/** Domain-separation tag prefixed to every governance signing payload. */
export const GOV_DOMAIN = "ce-gov-v1";

/** Artifact `kind` discriminators (the `kind` field of every artifact). */
export const KIND = Object.freeze({
  POLICY: "policy",
  PROPOSAL: "proposal",
  ARGUMENT: "argument",
  VOTE: "vote",
  VERDICT: "verdict",
  ABUSE_REPORT: "abuse_report",
  SCAN_REQUEST: "scan_request",
  SCAN_VERDICT: "scan_verdict",
  NODE_PROFILE: "node_profile",
});

/** Argument kinds. */
export const ARG_KIND = Object.freeze({ PROOF: "proof", ANTIPROOF: "antiproof" });

/** Vote directions. */
export const VOTE_DIR = Object.freeze({ UP: "up", DOWN: "down" });

/** Scan / verdict decisions. */
export const DECISION = Object.freeze({ ALLOW: "allow", DENY: "deny" });

/** Verdict / proposal lifecycle states. */
export const STATE = Object.freeze({
  OPEN: "open",
  CLOSED: "closed",
  ENACTED: "enacted",
  SUPERSEDED: "superseded",
});

// ---------------------------------------------------------------------------
// Amount — integer base-unit money as decimal strings (never floats)
// ---------------------------------------------------------------------------

/**
 * Amount helpers. All amounts cross the API as decimal strings of base units.
 * Internally we use BigInt; we never store a float.
 */
export const Amount = Object.freeze({
  /** @param {string} s @returns {bigint} */
  toBig(s) {
    if (typeof s !== "string" || !/^-?\d+$/.test(s)) {
      throw new TypeError(`Amount must be a decimal integer string, got: ${String(s)}`);
    }
    return BigInt(s);
  },
  /** @param {bigint} b @returns {string} */
  fromBig(b) {
    if (typeof b !== "bigint") throw new TypeError("fromBig expects a BigInt");
    return b.toString(10);
  },
  /** Parse a human credit decimal (e.g. "1.5") into a base-unit string. */
  fromCredits(creditsStr) {
    const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(String(creditsStr));
    if (!m) throw new TypeError(`bad credit amount: ${creditsStr}`);
    const sign = m[1] === "-" ? -1n : 1n;
    const whole = BigInt(m[2]);
    const fracRaw = (m[3] || "").slice(0, 18).padEnd(18, "0");
    return Amount.fromBig(sign * (whole * CREDIT + BigInt(fracRaw)));
  },
  /** Format a base-unit string as a human credit decimal (trimmed). */
  toCredits(s) {
    const b = Amount.toBig(s);
    const neg = b < 0n;
    const a = neg ? -b : b;
    const whole = a / CREDIT;
    const frac = (a % CREDIT).toString().padStart(18, "0").replace(/0+$/, "");
    return `${neg ? "-" : ""}${whole}${frac ? "." + frac : ""}`;
  },
  add(a, b) { return Amount.fromBig(Amount.toBig(a) + Amount.toBig(b)); },
  sub(a, b) { return Amount.fromBig(Amount.toBig(a) - Amount.toBig(b)); },
  cmp(a, b) { const x = Amount.toBig(a), y = Amount.toBig(b); return x < y ? -1 : x > y ? 1 : 0; },
  isZero(a) { return Amount.toBig(a) === 0n; },
});

// ---------------------------------------------------------------------------
// Canonical JSON + content hashing
// ---------------------------------------------------------------------------

/**
 * Serialize a value to canonical JSON: keys sorted at every depth, no extra
 * whitespace. Arrays keep order. Numbers must be integers (we forbid floats
 * to keep hashing deterministic). Used as the byte basis for hashing+signing.
 * @param {unknown} value
 * @returns {string}
 */
export function canonical(value) {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(v) {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number" && !Number.isInteger(v)) {
      throw new TypeError("non-integer numbers are forbidden in canonical JSON (use Amount strings)");
    }
    return v;
  }
  if (Array.isArray(v)) return v.map(sortDeep);
  const out = {};
  for (const k of Object.keys(v).sort()) {
    if (v[k] === undefined) continue; // drop undefined so optional fields don't change the hash
    out[k] = sortDeep(v[k]);
  }
  return out;
}

/** UTF-8 encode. */
function utf8(s) { return new TextEncoder().encode(s); }

/** Lowercase hex of a byte array. */
export function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** @param {string} hex @returns {Uint8Array} */
export function fromHex(hex) {
  if (hex.length % 2 !== 0) throw new TypeError("hex length must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * SHA-256 of arbitrary bytes -> lowercase hex. Web Crypto, works in Node>=18 + browsers.
 * @param {Uint8Array|ArrayBuffer} bytes
 * @returns {Promise<string>}
 */
export async function sha256Hex(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return toHex(new Uint8Array(digest));
}

/**
 * Content hash of a value via canonical JSON. This is the artifact `id`/CID basis.
 * @param {unknown} value
 * @returns {Promise<string>} 64-hex SHA-256
 */
export async function hashHex(value) {
  return sha256Hex(utf8(canonical(value)));
}

// ---------------------------------------------------------------------------
// Content addressing + signing payloads
// ---------------------------------------------------------------------------

/**
 * The bytes (as a string) that get HASHED to form an artifact id and SIGNED by
 * its author. We strip the volatile/derived fields (`id`, `sig`) and prefix the
 * domain tag + kind so a governance signature can never collide with another
 * CE signature. Both `id` and `sig` are computed over THIS exact string.
 * @param {object} artifact  any artifact object that has a `kind`
 * @returns {string}
 */
export function signingPayload(artifact) {
  const { id, sig, ...rest } = artifact;
  return `${GOV_DOMAIN}:${artifact.kind}:${canonical(rest)}`;
}

/**
 * Compute the content-addressed id of an artifact (over signingPayload).
 * Call this before signing; the same payload is what the author signs.
 * @param {object} artifact
 * @returns {Promise<string>} 64-hex id
 */
export async function artifactId(artifact) {
  return sha256Hex(utf8(signingPayload(artifact)));
}

// ---------------------------------------------------------------------------
// Schema validation (tiny, dependency-free)
// ---------------------------------------------------------------------------

/**
 * A schema is a frozen plain object: { field: spec, ... } where spec is one of:
 *   { type: 'string'|'int'|'amount'|'hex'|'bool'|'object', optional?, enum?, len?, of? }
 *   for arrays: { type: 'array', of: <spec> }
 * `validate` throws on the first violation; `isValid` returns a boolean.
 */
export function validate(obj, schema, where = "artifact") {
  if (obj === null || typeof obj !== "object") throw new TypeError(`${where}: not an object`);
  for (const [field, spec] of Object.entries(schema)) {
    const v = obj[field];
    if (v === undefined || v === null) {
      if (spec.optional) continue;
      throw new TypeError(`${where}.${field}: required`);
    }
    checkSpec(v, spec, `${where}.${field}`);
  }
  return obj;
}

function checkSpec(v, spec, where) {
  switch (spec.type) {
    case "string":
      if (typeof v !== "string") throw new TypeError(`${where}: expected string`);
      if (spec.enum && !spec.enum.includes(v)) throw new TypeError(`${where}: not in enum ${spec.enum}`);
      break;
    case "int":
      if (typeof v !== "number" || !Number.isInteger(v)) throw new TypeError(`${where}: expected integer`);
      break;
    case "bool":
      if (typeof v !== "boolean") throw new TypeError(`${where}: expected boolean`);
      break;
    case "amount":
      if (typeof v !== "string" || !/^-?\d+$/.test(v)) throw new TypeError(`${where}: expected base-unit decimal string`);
      break;
    case "hex":
      if (typeof v !== "string" || !/^[0-9a-f]*$/.test(v)) throw new TypeError(`${where}: expected lowercase hex`);
      if (spec.len !== undefined && v.length !== spec.len) throw new TypeError(`${where}: expected ${spec.len} hex chars`);
      break;
    case "object":
      if (typeof v !== "object" || Array.isArray(v)) throw new TypeError(`${where}: expected object`);
      break;
    case "array":
      if (!Array.isArray(v)) throw new TypeError(`${where}: expected array`);
      if (spec.of) v.forEach((el, i) => checkSpec(el, spec.of, `${where}[${i}]`));
      break;
    default:
      throw new TypeError(`${where}: unknown spec type ${spec.type}`);
  }
}

/** @returns {boolean} non-throwing validate. */
export function isValid(obj, schema) {
  try { validate(obj, schema); return true; } catch { return false; }
}

// ---------------------------------------------------------------------------
// Schemas (frozen) — one per artifact shape
// ---------------------------------------------------------------------------

/** A cited external source backing an argument. */
export const SourceSchema = Object.freeze({
  url: { type: "string" },
  title: { type: "string" },
  // trust: app-derived 0..100 confidence in the source domain (integer, not money)
  trust: { type: "int" },
});

export const PolicySchema = Object.freeze({
  kind: { type: "string", enum: [KIND.POLICY] },
  // human-readable category id, e.g. "pornographic_content", "cryptomining"
  category: { type: "string" },
  title: { type: "string" },
  description: { type: "string" },
  // 'deny' (banned) or 'allow' (explicitly permitted) — feeds Guardian banned_categories
  action: { type: "string", enum: [DECISION.ALLOW, DECISION.DENY] },
  // verdict id that enacted this policy (the chain of authority); empty for a default/seed policy
  verdict_id: { type: "hex", len: 64, optional: true },
  state: { type: "string", enum: Object.values(STATE) },
  ts: { type: "int" },
  author: { type: "hex", len: 64 },
  id: { type: "hex", len: 64, optional: true },
  sig: { type: "hex", len: 128, optional: true },
});

export const PolicyProposalSchema = Object.freeze({
  kind: { type: "string", enum: [KIND.PROPOSAL] },
  title: { type: "string" },
  // the proposed rule, e.g. "ban hosting of pornographic content"
  statement: { type: "string" },
  // the category id this proposal would create/modify if it passes
  category: { type: "string" },
  action: { type: "string", enum: [DECISION.ALLOW, DECISION.DENY] },
  // tags constraining who is considered an "expert" for this topic (e.g. ["security","legal"])
  expertise_tags: { type: "array", of: { type: "string" } },
  // block height at which voting opened, and the height it closes (deadline)
  open_height: { type: "int" },
  close_height: { type: "int" },
  state: { type: "string", enum: Object.values(STATE) },
  ts: { type: "int" },
  author: { type: "hex", len: 64 },
  id: { type: "hex", len: 64, optional: true },
  sig: { type: "hex", len: 128, optional: true },
});

export const ArgumentSchema = Object.freeze({
  kind: { type: "string", enum: [KIND.ARGUMENT] },
  proposal_id: { type: "hex", len: 64 },
  // 'proof' = supports the proposal; 'antiproof' = opposes it
  arg_kind: { type: "string", enum: Object.values(ARG_KIND) },
  body: { type: "string" },
  // external trusted sources are REQUIRED for an argument to be weighted
  sources: { type: "array", of: { type: "object" } },
  ts: { type: "int" },
  author: { type: "hex", len: 64 },
  id: { type: "hex", len: 64, optional: true },
  sig: { type: "hex", len: 128, optional: true },
});

export const VoteSchema = Object.freeze({
  kind: { type: "string", enum: [KIND.VOTE] },
  proposal_id: { type: "hex", len: 64 },
  // a vote may target the proposal directly (argument_id omitted) or a specific argument
  argument_id: { type: "hex", len: 64, optional: true },
  direction: { type: "string", enum: Object.values(VOTE_DIR) },
  // raw reputation weight (base-unit string) the voter brings; the tally applies quadratic damping
  weight: { type: "amount" },
  // beacon height+hash sampled at vote time (anti-grind provenance)
  beacon_height: { type: "int" },
  beacon_hash: { type: "hex", len: 64 },
  ts: { type: "int" },
  author: { type: "hex", len: 64 },
  id: { type: "hex", len: 64, optional: true },
  sig: { type: "hex", len: 128, optional: true },
});

export const VerdictSchema = Object.freeze({
  kind: { type: "string", enum: [KIND.VERDICT] },
  proposal_id: { type: "hex", len: 64 },
  // tallied outcome
  decision: { type: "string", enum: Object.values(DECISION) },
  // effective weighted tallies, base-unit strings (post quadratic damping)
  tally_for: { type: "amount" },
  tally_against: { type: "amount" },
  voter_count: { type: "int" },
  // the policy this verdict enacts if decision === 'deny'/'allow' (the resulting active policy id)
  policy_id: { type: "hex", len: 64, optional: true },
  // beacon at finalization for auditability
  beacon_height: { type: "int" },
  beacon_hash: { type: "hex", len: 64 },
  state: { type: "string", enum: Object.values(STATE) },
  ts: { type: "int" },
  author: { type: "hex", len: 64 },
  id: { type: "hex", len: 64, optional: true },
  sig: { type: "hex", len: 128, optional: true },
});

export const AbuseReportSchema = Object.freeze({
  kind: { type: "string", enum: [KIND.ABUSE_REPORT] },
  // the offending workload: content digest (image digest / wasm module hash) and the job id
  artifact_digest: { type: "hex", len: 64 },
  job_id: { type: "hex", len: 64 },
  // the host that ran it (the slash target candidate)
  host: { type: "hex", len: 64 },
  // the policy category violated (must reference an active policy category)
  category: { type: "string" },
  // 'deny' once classified abusive; severity 0..100 (integer, not money)
  decision: { type: "string", enum: Object.values(DECISION) },
  severity: { type: "int" },
  evidence: { type: "string" },
  // optional verdict id from the validator (LLM/ce-infer) backing the classification
  validator_verdict_id: { type: "hex", len: 64, optional: true },
  beacon_height: { type: "int" },
  beacon_hash: { type: "hex", len: 64 },
  ts: { type: "int" },
  author: { type: "hex", len: 64 },
  id: { type: "hex", len: 64, optional: true },
  sig: { type: "hex", len: 128, optional: true },
});

export const ScanRequestSchema = Object.freeze({
  kind: { type: "string", enum: [KIND.SCAN_REQUEST] },
  // 'docker' | 'wasm'
  artifact_type: { type: "string", enum: ["docker", "wasm"] },
  // content digest of the exact bytes that will execute (image pinned digest / module hash)
  artifact_digest: { type: "hex", len: 64 },
  // open-source location of the artifact's source (required: must be open-source to run)
  source_url: { type: "string" },
  // declared entrypoint/cmd, env keys (no values), and declared resource shape
  cmd: { type: "array", of: { type: "string" } },
  env_keys: { type: "array", of: { type: "string" } },
  cpu_cores: { type: "int" },
  mem_mb: { type: "int" },
  // the policy set version (id) this request is scanned against
  policy_set_id: { type: "hex", len: 64 },
  payer: { type: "hex", len: 64 },
  ts: { type: "int" },
  author: { type: "hex", len: 64 },
  id: { type: "hex", len: 64, optional: true },
  sig: { type: "hex", len: 128, optional: true },
});

export const ScanVerdictSchema = Object.freeze({
  kind: { type: "string", enum: [KIND.SCAN_VERDICT] },
  // the digest this verdict is cached under (== ScanRequest.artifact_digest)
  artifact_digest: { type: "hex", len: 64 },
  scan_request_id: { type: "hex", len: 64 },
  policy_set_id: { type: "hex", len: 64 },
  decision: { type: "string", enum: Object.values(DECISION) },
  // matched/violated category ids
  categories: { type: "array", of: { type: "string" } },
  // 0..100 integer confidence
  confidence: { type: "int" },
  rationale: { type: "string" },
  // reproducibility provenance: which model/template/rules produced this (per guardian.md)
  model_id: { type: "string", optional: true },
  prompt_template_hash: { type: "hex", len: 64, optional: true },
  rule_pack_version: { type: "string", optional: true },
  // true if produced by deterministic checks only (hard verdict); false if LLM-advisory
  deterministic: { type: "bool" },
  ts: { type: "int" },
  author: { type: "hex", len: 64 },
  id: { type: "hex", len: 64, optional: true },
  sig: { type: "hex", len: 128, optional: true },
});

export const NodeProfileLiteSchema = Object.freeze({
  kind: { type: "string", enum: [KIND.NODE_PROFILE] },
  node_id: { type: "hex", len: 64 },
  // derived reputation scalars (NOT money) — see reputation.js
  karma: { type: "int" },
  // per-tag expertise map, integer scores; serialized as an object of tag->int
  expertise: { type: "object" },
  // the raw NodeStats-derived figures kept for transparency (base-unit strings)
  earned: { type: "amount" },
  recent_earned: { type: "amount" },
  jobs_hosted: { type: "int" },
  slashes: { type: "int" },
  expiries: { type: "int" },
  // height at which this profile was computed (provenance)
  at_height: { type: "int" },
  ts: { type: "int" },
});

/** Map kind -> schema, for generic verification. */
export const SCHEMA_BY_KIND = Object.freeze({
  [KIND.POLICY]: PolicySchema,
  [KIND.PROPOSAL]: PolicyProposalSchema,
  [KIND.ARGUMENT]: ArgumentSchema,
  [KIND.VOTE]: VoteSchema,
  [KIND.VERDICT]: VerdictSchema,
  [KIND.ABUSE_REPORT]: AbuseReportSchema,
  [KIND.SCAN_REQUEST]: ScanRequestSchema,
  [KIND.SCAN_VERDICT]: ScanVerdictSchema,
  [KIND.NODE_PROFILE]: NodeProfileLiteSchema,
});

// ---------------------------------------------------------------------------
// JSDoc typedefs (for editors / implementers)
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} Source
 * @property {string} url
 * @property {string} title
 * @property {number} trust  app-derived 0..100 confidence in the source
 */

/**
 * @typedef {Object} Policy
 * @property {'policy'} kind
 * @property {string} category
 * @property {string} title
 * @property {string} description
 * @property {'allow'|'deny'} action
 * @property {string} [verdict_id]
 * @property {string} state
 * @property {number} ts
 * @property {string} author
 * @property {string} [id]
 * @property {string} [sig]
 */

/**
 * @typedef {Object} PolicyProposal
 * @property {'proposal'} kind
 * @property {string} title
 * @property {string} statement
 * @property {string} category
 * @property {'allow'|'deny'} action
 * @property {string[]} expertise_tags
 * @property {number} open_height
 * @property {number} close_height
 * @property {string} state
 * @property {number} ts
 * @property {string} author
 * @property {string} [id]
 * @property {string} [sig]
 */

/**
 * @typedef {Object} Argument
 * @property {'argument'} kind
 * @property {string} proposal_id
 * @property {'proof'|'antiproof'} arg_kind
 * @property {string} body
 * @property {Source[]} sources
 * @property {number} ts
 * @property {string} author
 * @property {string} [id]
 * @property {string} [sig]
 */

/**
 * @typedef {Object} Vote
 * @property {'vote'} kind
 * @property {string} proposal_id
 * @property {string} [argument_id]
 * @property {'up'|'down'} direction
 * @property {string} weight   base-unit decimal string
 * @property {number} beacon_height
 * @property {string} beacon_hash
 * @property {number} ts
 * @property {string} author
 * @property {string} [id]
 * @property {string} [sig]
 */

/**
 * @typedef {Object} Verdict
 * @property {'verdict'} kind
 * @property {string} proposal_id
 * @property {'allow'|'deny'} decision
 * @property {string} tally_for       base-unit decimal string
 * @property {string} tally_against   base-unit decimal string
 * @property {number} voter_count
 * @property {string} [policy_id]
 * @property {number} beacon_height
 * @property {string} beacon_hash
 * @property {string} state
 * @property {number} ts
 * @property {string} author
 * @property {string} [id]
 * @property {string} [sig]
 */

/**
 * @typedef {Object} AbuseReport
 * @property {'abuse_report'} kind
 * @property {string} artifact_digest
 * @property {string} job_id
 * @property {string} host
 * @property {string} category
 * @property {'allow'|'deny'} decision
 * @property {number} severity
 * @property {string} evidence
 * @property {string} [validator_verdict_id]
 * @property {number} beacon_height
 * @property {string} beacon_hash
 * @property {number} ts
 * @property {string} author
 * @property {string} [id]
 * @property {string} [sig]
 */

/**
 * @typedef {Object} ScanRequest
 * @property {'scan_request'} kind
 * @property {'docker'|'wasm'} artifact_type
 * @property {string} artifact_digest
 * @property {string} source_url
 * @property {string[]} cmd
 * @property {string[]} env_keys
 * @property {number} cpu_cores
 * @property {number} mem_mb
 * @property {string} policy_set_id
 * @property {string} payer
 * @property {number} ts
 * @property {string} author
 * @property {string} [id]
 * @property {string} [sig]
 */

/**
 * @typedef {Object} ScanVerdict
 * @property {'scan_verdict'} kind
 * @property {string} artifact_digest
 * @property {string} scan_request_id
 * @property {string} policy_set_id
 * @property {'allow'|'deny'} decision
 * @property {string[]} categories
 * @property {number} confidence
 * @property {string} rationale
 * @property {string} [model_id]
 * @property {string} [prompt_template_hash]
 * @property {string} [rule_pack_version]
 * @property {boolean} deterministic
 * @property {number} ts
 * @property {string} author
 * @property {string} [id]
 * @property {string} [sig]
 */

/**
 * @typedef {Object} NodeProfileLite
 * @property {'node_profile'} kind
 * @property {string} node_id
 * @property {number} karma
 * @property {Object<string,number>} expertise
 * @property {string} earned
 * @property {string} recent_earned
 * @property {number} jobs_hosted
 * @property {number} slashes
 * @property {number} expiries
 * @property {number} at_height
 * @property {number} ts
 */

// ---------------------------------------------------------------------------
// Factory functions — build a normalized, schema-valid object (no id/sig yet)
// ---------------------------------------------------------------------------

const now = () => Date.now();

/** @param {Partial<Source>} s @returns {Source} */
export function makeSource(s) {
  const out = { url: String(s.url), title: String(s.title || ""), trust: s.trust | 0 };
  validate(out, SourceSchema, "source");
  return out;
}

/** @param {Partial<Policy>} p @returns {Policy} */
export function makePolicy(p) {
  const out = {
    kind: KIND.POLICY,
    category: p.category,
    title: p.title || "",
    description: p.description || "",
    action: p.action || DECISION.DENY,
    verdict_id: p.verdict_id,
    state: p.state || STATE.ENACTED,
    ts: p.ts ?? now(),
    author: p.author,
  };
  return validate(out, PolicySchema, "policy");
}

/** @param {Partial<PolicyProposal>} p @returns {PolicyProposal} */
export function makeProposal(p) {
  const out = {
    kind: KIND.PROPOSAL,
    title: p.title,
    statement: p.statement,
    category: p.category,
    action: p.action || DECISION.DENY,
    expertise_tags: p.expertise_tags || [],
    open_height: p.open_height | 0,
    close_height: p.close_height | 0,
    state: p.state || STATE.OPEN,
    ts: p.ts ?? now(),
    author: p.author,
  };
  return validate(out, PolicyProposalSchema, "proposal");
}

/** @param {Partial<Argument>} a @returns {Argument} */
export function makeArgument(a) {
  const out = {
    kind: KIND.ARGUMENT,
    proposal_id: a.proposal_id,
    arg_kind: a.arg_kind,
    body: a.body,
    sources: (a.sources || []).map(makeSource),
    ts: a.ts ?? now(),
    author: a.author,
  };
  return validate(out, ArgumentSchema, "argument");
}

/** @param {Partial<Vote>} v @returns {Vote} */
export function makeVote(v) {
  const out = {
    kind: KIND.VOTE,
    proposal_id: v.proposal_id,
    argument_id: v.argument_id,
    direction: v.direction,
    weight: v.weight ?? "0",
    beacon_height: v.beacon_height | 0,
    beacon_hash: v.beacon_hash,
    ts: v.ts ?? now(),
    author: v.author,
  };
  return validate(out, VoteSchema, "vote");
}

/** @param {Partial<Verdict>} v @returns {Verdict} */
export function makeVerdict(v) {
  const out = {
    kind: KIND.VERDICT,
    proposal_id: v.proposal_id,
    decision: v.decision,
    tally_for: v.tally_for ?? "0",
    tally_against: v.tally_against ?? "0",
    voter_count: v.voter_count | 0,
    policy_id: v.policy_id,
    beacon_height: v.beacon_height | 0,
    beacon_hash: v.beacon_hash,
    state: v.state || STATE.CLOSED,
    ts: v.ts ?? now(),
    author: v.author,
  };
  return validate(out, VerdictSchema, "verdict");
}

/** @param {Partial<AbuseReport>} r @returns {AbuseReport} */
export function makeAbuseReport(r) {
  const out = {
    kind: KIND.ABUSE_REPORT,
    artifact_digest: r.artifact_digest,
    job_id: r.job_id,
    host: r.host,
    category: r.category,
    decision: r.decision || DECISION.DENY,
    severity: r.severity | 0,
    evidence: r.evidence || "",
    validator_verdict_id: r.validator_verdict_id,
    beacon_height: r.beacon_height | 0,
    beacon_hash: r.beacon_hash,
    ts: r.ts ?? now(),
    author: r.author,
  };
  return validate(out, AbuseReportSchema, "abuse_report");
}

/** @param {Partial<ScanRequest>} r @returns {ScanRequest} */
export function makeScanRequest(r) {
  const out = {
    kind: KIND.SCAN_REQUEST,
    artifact_type: r.artifact_type,
    artifact_digest: r.artifact_digest,
    source_url: r.source_url,
    cmd: r.cmd || [],
    env_keys: r.env_keys || [],
    cpu_cores: r.cpu_cores | 0,
    mem_mb: r.mem_mb | 0,
    policy_set_id: r.policy_set_id,
    payer: r.payer,
    ts: r.ts ?? now(),
    author: r.author,
  };
  return validate(out, ScanRequestSchema, "scan_request");
}

/** @param {Partial<ScanVerdict>} v @returns {ScanVerdict} */
export function makeScanVerdict(v) {
  const out = {
    kind: KIND.SCAN_VERDICT,
    artifact_digest: v.artifact_digest,
    scan_request_id: v.scan_request_id,
    policy_set_id: v.policy_set_id,
    decision: v.decision,
    categories: v.categories || [],
    confidence: v.confidence | 0,
    rationale: v.rationale || "",
    model_id: v.model_id,
    prompt_template_hash: v.prompt_template_hash,
    rule_pack_version: v.rule_pack_version,
    deterministic: v.deterministic ?? false,
    ts: v.ts ?? now(),
    author: v.author,
  };
  return validate(out, ScanVerdictSchema, "scan_verdict");
}

/** @param {Partial<NodeProfileLite>} p @returns {NodeProfileLite} */
export function makeNodeProfileLite(p) {
  const out = {
    kind: KIND.NODE_PROFILE,
    node_id: p.node_id,
    karma: p.karma | 0,
    expertise: p.expertise || {},
    earned: p.earned ?? "0",
    recent_earned: p.recent_earned ?? "0",
    jobs_hosted: p.jobs_hosted | 0,
    slashes: p.slashes | 0,
    expiries: p.expiries | 0,
    at_height: p.at_height | 0,
    ts: p.ts ?? now(),
  };
  return validate(out, NodeProfileLiteSchema, "node_profile");
}

/**
 * Finalize an artifact: compute its content id, attach it, and (if a signer is
 * supplied) attach the author signature over the same signing payload.
 *
 * `signer` is an async fn (payloadString) => 128-hex signature. Identity/signing
 * is a node-key operation; the caller wires it (CLI signs via ce-cap/identity,
 * the browser via the wallet). With no signer the artifact is content-addressed
 * but unsigned (useful for local computation / tests).
 *
 * @template {object} T
 * @param {T} artifact
 * @param {(payload: string) => Promise<string>} [signer]
 * @returns {Promise<T & {id: string, sig?: string}>}
 */
export async function finalize(artifact, signer) {
  const payload = signingPayload(artifact);
  const id = await sha256Hex(utf8(payload));
  const out = { ...artifact, id };
  if (signer) out.sig = await signer(payload);
  return out;
}
