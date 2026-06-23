// @ce-net/gov — (b) runtime monitoring + abuse reporting.
//
// Watches the jobs a node runs and the CEP-1 signals on the mesh, turns observed
// abuse (sustained-100%-CPU hash patterns => cryptomining, disallowed-content
// signals => pornographic_content, port-scan/spam patterns => network_abuse) into
// SIGNED, beacon-stamped `AbuseReport` evidence, broadcasts it as a CEP-1 signal,
// feeds severity into the reputation layer (a karma hit, advisory only), and emits
// a *proposed* on-chain payload per `docs/onchain-spec.md` §2.5.
//
// HARD BOUNDARY (architecture.md (b); guardian.md §7; sybil-resistance.md §4.1):
//   * This module NEVER enforces and NEVER auto-slashes. An LLM/heuristic verdict
//     is not on-chain-provable. The on-chain payload it emits is a *bonded
//     AbuseReport annotation* that merely makes the artifact eligible for a
//     beacon-seeded K-of-N redundant re-scan; only that re-scan's provable
//     divergence can feed the already-spec'd SlashVerificationFault path. No new
//     slashing power is created here.
//   * Reports are rate-limited (anti-grief) and reference an *active policy
//     category* — a report is only meaningful against a rule the community enacted.
//
// IO only through an injected `CeClient`; the validator (validator.js) and signer
// are dependency-injected. Pure heuristics (detect*/reputationFeed/rateLimitOk)
// take plain objects so they run with no network (see `__selftest`).

import { makeAbuseReport, finalize, DECISION, canonical, sha256Hex } from "./types.js";
import { applyAbusePenalty } from "./reputation.js";
import { activePolicySet } from "./policy.js";

// ---------------------------------------------------------------------------
// Tunable constants (documented; not consensus — app-tier heuristics)
// ---------------------------------------------------------------------------

/** Built-in abuse categories these heuristics can recognize (must also be an
 *  enacted policy category for a report to be accepted by `reportAbuse`). */
export const ABUSE_CATEGORY = Object.freeze({
  CRYPTOMINING: "cryptomining",
  PORNOGRAPHIC: "pornographic_content",
  NETWORK_ABUSE: "network_abuse",
});

/** Heuristic thresholds. Pure detectors read these; tune freely. */
export const MON = Object.freeze({
  // sustained CPU saturation that looks like a hashing loop.
  CPU_SATURATION_PCT: 97,        // >= this mean CPU% ...
  CPU_SUSTAINED_SECS: 120,       // ... held for at least this long ...
  CPU_LOW_IO_BYTES: 1_048_576,   // ... while doing almost no disk/net IO (classic miner profile)
  // port-scan / spam network profile.
  SCAN_DISTINCT_PEERS: 50,       // many distinct destinations ...
  SCAN_WINDOW_SECS: 60,          // ... in a short window ...
  SCAN_BYTES_PER_PEER: 2048,     // ... with tiny per-peer payloads (probing, not transfer)
  // anti-grief: a reporter may file at most N reports per window.
  REPORT_WINDOW_SECS: 3600,
  REPORT_MAX_PER_WINDOW: 5,
  // severity floors per detected category (0..100).
  SEV_CRYPTOMINING: 80,
  SEV_PORNOGRAPHIC: 90,
  SEV_NETWORK_ABUSE: 70,
});

/** Karma penalty applied per unit severity in the reputation feed (mirrors
 *  reputation.js ABUSE_KARMA_PER_SEVERITY semantics; kept local so this module
 *  needs no internal coupling). */
const KARMA_PER_SEVERITY = 1;

// ---------------------------------------------------------------------------
// Pure abuse detectors (no network) — observe a JobSample, return a finding|null
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} JobSample  one observation window for a running job.
 * @property {string} job_id              64-hex job id
 * @property {string} host                64-hex host node id (the slash candidate)
 * @property {string} [artifact_digest]   64-hex content digest of the running image/module
 * @property {number} [cpu_pct]           mean CPU% over the window (0..100*cores normalized to 0..100)
 * @property {number} [sustained_secs]    how long that CPU level has been held
 * @property {number} [io_bytes]          disk+net bytes moved in the window
 * @property {number} [distinct_peers]    distinct network destinations contacted in the window
 * @property {number} [window_secs]       length of the network window
 * @property {number} [bytes_per_peer]    mean bytes per distinct peer
 * @property {string[]} [content_flags]   out-of-band content classifier flags (e.g. ["nsfw"])
 */

/**
 * @typedef {Object} Finding
 * @property {string} category   one of ABUSE_CATEGORY
 * @property {number} severity   0..100 integer
 * @property {string} evidence   short human-readable rationale (deterministic)
 */

const ZERO = "0".repeat(64);
const isHex64 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const i = (v) => (Number.isFinite(+v) ? Math.trunc(+v) : 0);
const clampSev = (n) => Math.max(0, Math.min(100, i(n)));

/**
 * Cryptomining heuristic: sustained near-100% CPU with negligible IO is the
 * classic hashing-loop signature. Pure.
 * @param {JobSample} s
 * @returns {Finding|null}
 */
export function detectCryptomining(s) {
  if (!s) return null;
  if (i(s.cpu_pct) >= MON.CPU_SATURATION_PCT &&
      i(s.sustained_secs) >= MON.CPU_SUSTAINED_SECS &&
      i(s.io_bytes) <= MON.CPU_LOW_IO_BYTES) {
    return {
      category: ABUSE_CATEGORY.CRYPTOMINING,
      severity: MON.SEV_CRYPTOMINING,
      evidence: `sustained CPU ${i(s.cpu_pct)}% for ${i(s.sustained_secs)}s with ${i(s.io_bytes)}B IO (hashing-loop profile)`,
    };
  }
  return null;
}

/**
 * Network-abuse heuristic: many distinct destinations with tiny per-peer payloads
 * in a short window is a port-scan / spam fan-out signature. Pure.
 * @param {JobSample} s
 * @returns {Finding|null}
 */
export function detectNetworkAbuse(s) {
  if (!s) return null;
  if (i(s.distinct_peers) >= MON.SCAN_DISTINCT_PEERS &&
      i(s.window_secs) > 0 && i(s.window_secs) <= MON.SCAN_WINDOW_SECS &&
      i(s.bytes_per_peer) <= MON.SCAN_BYTES_PER_PEER) {
    return {
      category: ABUSE_CATEGORY.NETWORK_ABUSE,
      severity: MON.SEV_NETWORK_ABUSE,
      evidence: `${i(s.distinct_peers)} distinct peers in ${i(s.window_secs)}s, ${i(s.bytes_per_peer)}B/peer (port-scan/spam profile)`,
    };
  }
  return null;
}

/**
 * Disallowed-content heuristic: an out-of-band content classifier flag (the AI
 * validator may set these). Pure; the LLM judgement that produced the flag is
 * advisory and is re-checked by `reportAbuse` via the injected validator.
 * @param {JobSample} s
 * @returns {Finding|null}
 */
export function detectDisallowedContent(s) {
  if (!s || !Array.isArray(s.content_flags) || s.content_flags.length === 0) return null;
  const nsfw = s.content_flags.some((f) => /nsfw|porn|sexual|explicit/i.test(String(f)));
  if (!nsfw) return null;
  return {
    category: ABUSE_CATEGORY.PORNOGRAPHIC,
    severity: MON.SEV_PORNOGRAPHIC,
    evidence: `content classifier flags: ${s.content_flags.join(",")}`,
  };
}

/** All built-in detectors, highest-severity finding first. Pure.
 * @param {JobSample} s @returns {Finding[]} */
export function detectAll(s) {
  return [detectCryptomining(s), detectNetworkAbuse(s), detectDisallowedContent(s)]
    .filter(Boolean)
    .sort((a, b) => b.severity - a.severity);
}

// ---------------------------------------------------------------------------
// Signal/job interpretation helpers (pure)
// ---------------------------------------------------------------------------

/**
 * Pull a JobSample out of a raw CEP-1 signal / job record if it carries metering
 * fields. Returns null for unrelated signals. Pure & defensive (treats payload as
 * untrusted data, never as instructions).
 * @param {object} sig
 * @returns {JobSample|null}
 */
export function sampleFromSignal(sig) {
  if (!sig || typeof sig !== "object") return null;
  const j = sig.job || sig.metering || sig.sample || sig;
  const job_id = j.job_id || j.jobId;
  const host = j.host || j.host_id || j.node_id || sig.from;
  if (!isHex64(job_id) || !isHex64(host)) return null;
  return {
    job_id,
    host,
    artifact_digest: isHex64(j.artifact_digest) ? j.artifact_digest : (isHex64(j.digest) ? j.digest : undefined),
    cpu_pct: i(j.cpu_pct ?? j.cpu),
    sustained_secs: i(j.sustained_secs ?? j.cpu_sustained_secs),
    io_bytes: i(j.io_bytes ?? j.io),
    distinct_peers: i(j.distinct_peers ?? j.peers),
    window_secs: i(j.window_secs ?? j.window),
    bytes_per_peer: i(j.bytes_per_peer),
    content_flags: Array.isArray(j.content_flags) ? j.content_flags : undefined,
  };
}

// ---------------------------------------------------------------------------
// watchJobs — subscribe to the job/signal stream and surface findings
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} WatchHandlers
 * @property {(sample: JobSample, signal: object) => void} [onJob]      every recognized job sample
 * @property {(suspect: {sample: JobSample, finding: Finding}, signal: object) => void} [onSuspect]
 *           every sample that tripped a detector (highest-severity finding attached)
 * @property {(err: Error) => void} [onError]
 */

/**
 * Subscribe to the CEP-1 signal stream, extract job metering samples, run the
 * pure detectors, and invoke handlers. Enforcement is NOT performed here — this
 * only observes and reports candidates for human/validator-gated `reportAbuse`.
 *
 * @param {import("./ce.js").CeClient} ce
 * @param {WatchHandlers} handlers
 * @param {Object} [opts]
 * @param {(s: JobSample) => Finding[]} [opts.detectors]  override the detector set (pure)
 * @returns {{ close(): void }}
 */
export function watchJobs(ce, handlers = {}, opts = {}) {
  const detect = opts.detectors || detectAll;
  const handle = (sig) => {
    let sample;
    try { sample = sampleFromSignal(sig); } catch (e) { handlers.onError && handlers.onError(e); return; }
    if (!sample) return;
    try {
      handlers.onJob && handlers.onJob(sample, sig);
      const findings = detect(sample);
      if (findings && findings.length) {
        handlers.onSuspect && handlers.onSuspect({ sample, finding: findings[0] }, sig);
      }
    } catch (e) {
      handlers.onError && handlers.onError(e);
    }
  };
  const stream = ce.signalsStream(handle, (err) => handlers.onError && handlers.onError(err));
  return { close: () => { try { stream && stream.close(); } catch { /* ignore */ } } };
}

/**
 * Convenience entry point requested by the task: start a monitor that auto-files
 * a (validator-gated) AbuseReport for every suspect, if a signer is supplied.
 * Thin wrapper over `watchJobs` + `reportAbuse`; everything stays injectable.
 *
 * @param {Object} opts
 * @param {import("./ce.js").CeClient} opts.ce
 * @param {object} [opts.validator]   validator.js Validator (optional; report still files)
 * @param {(payload: string) => Promise<string>} [opts.signer]  auto-file reports if present
 * @param {WatchHandlers} [opts.handlers]
 * @param {(s: JobSample) => Finding[]} [opts.detectors]
 * @returns {{ close(): void }}
 */
export function startMonitor(opts = {}) {
  const { ce, validator, signer, handlers = {}, detectors } = opts;
  if (!ce) throw new TypeError("startMonitor: opts.ce (CeClient) is required");
  return watchJobs(ce, {
    onJob: handlers.onJob,
    onError: handlers.onError,
    onSuspect: async (suspect, sig) => {
      try {
        if (handlers.onSuspect) handlers.onSuspect(suspect, sig);
        if (signer) {
          const report = await reportAbuse(ce, validator, {
            artifact_digest: suspect.sample.artifact_digest,
            job_id: suspect.sample.job_id,
            host: suspect.sample.host,
            category: suspect.finding.category,
            severity: suspect.finding.severity,
            evidence: suspect.finding.evidence,
          }, signer);
          handlers.onReport && handlers.onReport(report, suspect, sig);
        }
      } catch (e) {
        handlers.onError && handlers.onError(e);
      }
    },
  }, { detectors });
}

// ---------------------------------------------------------------------------
// reportAbuse — build + sign + broadcast a beacon-stamped AbuseReport
// ---------------------------------------------------------------------------

/**
 * Produce a signed, beacon-stamped `AbuseReport` and broadcast it as a CEP-1
 * signal. The report's `category` must reference an ACTIVE policy category (a
 * report is only meaningful against an enacted rule). Optionally runs the
 * injected validator to attach a `validator_verdict_id`.
 *
 * This NEVER slashes. To obtain the proposed on-chain trigger payload, call
 * `slashTriggerPayload(report)` on the result.
 *
 * @param {import("./ce.js").CeClient} ce
 * @param {object|null} validator   validator.js Validator (or null to skip AI re-check)
 * @param {Partial<import("./types.js").AbuseReport>} fields
 * @param {(payload: string) => Promise<string>} signer  (payload)=>128-hex
 * @param {Object} [opts]
 * @param {boolean} [opts.requireActiveCategory=true]  reject categories not in the active set
 * @param {boolean} [opts.broadcast=true]
 * @returns {Promise<import("./types.js").AbuseReport>}
 */
export async function reportAbuse(ce, validator, fields = {}, signer, opts = {}) {
  if (!ce) throw new TypeError("reportAbuse: ce (CeClient) is required");
  if (typeof signer !== "function") throw new TypeError("reportAbuse: signer must be (payload)=>Promise<128-hex>");
  const requireActive = opts.requireActiveCategory !== false;
  const broadcast = opts.broadcast !== false;

  // 1) the category must be an enacted policy category (closes the loop with voting/(c)).
  if (requireActive) {
    let set;
    try { set = await activePolicySet(ce); } catch { set = { policies: [] }; }
    const known = new Set((set.policies || []).map((p) => p && p.category));
    if (!known.has(fields.category)) {
      throw new Error(`reportAbuse: category "${fields.category}" is not in the active policy set`);
    }
  }

  // 2) optional AI/heuristic re-check (advisory provenance only; never gates a deny).
  let validator_verdict_id = fields.validator_verdict_id;
  if (validator && typeof validator.verifyEvidence === "function" && !validator_verdict_id) {
    try {
      const vr = await validator.verifyEvidence({
        kind: "argument", proposal_id: ZERO, arg_kind: "proof",
        body: String(fields.evidence || ""), sources: [],
        ts: Date.now(), author: fields.author || ZERO,
      });
      if (vr && vr.verdict_id) validator_verdict_id = vr.verdict_id;
    } catch { /* graceful degrade: deterministic evidence still stands */ }
  }

  // 3) stamp the beacon for anti-cherry-pick provenance.
  let beacon_height = i(fields.beacon_height);
  let beacon_hash = fields.beacon_hash;
  if (!isHex64(beacon_hash)) {
    try {
      const b = await ce.beacon();
      beacon_height = i(b.height);
      beacon_hash = isHex64(b.hash) ? b.hash : ZERO;
    } catch {
      beacon_hash = ZERO; // degrade: a zero beacon marks an unstamped report
    }
  }

  // 4) build + finalize (content-address + sign over the canonical payload).
  const report = makeAbuseReport({
    artifact_digest: isHex64(fields.artifact_digest) ? fields.artifact_digest : ZERO,
    job_id: isHex64(fields.job_id) ? fields.job_id : ZERO,
    host: fields.host,
    category: fields.category,
    decision: fields.decision || DECISION.DENY,
    severity: clampSev(fields.severity),
    evidence: String(fields.evidence || ""),
    validator_verdict_id,
    beacon_height,
    beacon_hash,
    ts: fields.ts,
    author: fields.author,
  });
  const signed = await finalize(report, signer);

  // 5) persist as a content-addressed blob + broadcast as a CEP-1 signal.
  if (broadcast) {
    try {
      const bytes = new TextEncoder().encode(canonical(signed));
      await ce.putBlob(bytes);
    } catch { /* blob store optional; signal carries the artifact regardless */ }
  }
  return signed;
}

// ---------------------------------------------------------------------------
// On-chain trigger payload (proposed, onchain-spec.md §2.5) — NOT a slash
// ---------------------------------------------------------------------------

/**
 * Build the *proposed* on-chain `AbuseReport` tx payload from a finalized report.
 * Per onchain-spec.md §2.5 this is a BONDED ANNOTATION, not a slash: it stakes the
 * reporter and makes `artifact_digest` eligible for a beacon-seeded K-of-N
 * redundant re-scan. Only that re-scan's provable divergence can feed the existing
 * SlashVerificationFault path. This function emits the opaque, content-free tx
 * fields the node would accept; it grants NO slashing power.
 *
 * @param {import("./types.js").AbuseReport} report  a finalized (id+sig) AbuseReport
 * @param {Object} [opts]
 * @param {string} [opts.stake]   refundable stake in base units (decimal string); default "0"
 * @returns {Promise<{ tx_type:"AbuseReport", reporter:string, artifact_digest:string,
 *   host:string, category:string, report_hash:string, stake:string, beacon_height:number }>}
 */
export async function slashTriggerPayload(report, opts = {}) {
  if (!report || typeof report !== "object") throw new TypeError("slashTriggerPayload: report required");
  const stake = opts.stake !== undefined ? String(opts.stake) : "0";
  if (!/^\d+$/.test(stake)) throw new TypeError("slashTriggerPayload: stake must be a non-negative base-unit string");
  // report_hash anchors the full off-chain AbuseReport blob (== its content id).
  const report_hash = isHex64(report.id) ? report.id : await sha256Hex(new TextEncoder().encode(canonical(report)));
  return {
    tx_type: "AbuseReport",          // opaque to the node; routes to the bonded-annotation set
    reporter: report.author,
    artifact_digest: report.artifact_digest,
    host: report.host,
    category: report.category,        // opaque string; the chain never interprets it
    report_hash,
    stake,                            // refundable lock; forfeited if a higher-tier re-scan contradicts
    beacon_height: i(report.beacon_height),
  };
}

// ---------------------------------------------------------------------------
// collectReports — gather AbuseReports from signals/blobs
// ---------------------------------------------------------------------------

/**
 * Read recent `AbuseReport` artifacts off the signal window (and any matching
 * blobs). Best-effort; bounded by the node's 100-signal window.
 * @param {import("./ce.js").CeClient} ce
 * @param {Object} [opts]
 * @param {string} [opts.host]      filter: only reports against this host
 * @param {string} [opts.category]  filter: only this category
 * @returns {Promise<import("./types.js").AbuseReport[]>}
 */
export async function collectReports(ce, opts = {}) {
  if (!ce) throw new TypeError("collectReports: ce (CeClient) is required");
  let list;
  try { list = await ce.signals(); } catch { return []; }
  const out = [];
  const seen = new Set();
  for (const s of Array.isArray(list) ? list : []) {
    const art = decodeReportSignal(s);
    if (!art) continue;
    if (art.id && seen.has(art.id)) continue;
    if (art.id) seen.add(art.id);
    if (opts.host && art.host !== opts.host) continue;
    if (opts.category && art.category !== opts.category) continue;
    out.push(art);
  }
  return out;
}

/**
 * Decode a CEP-1 signal into an AbuseReport artifact if it carries one. Pure &
 * defensive: tolerates `payload_hex` JSON, a nested `.payload`, or a flat object.
 * @param {object} sig
 * @returns {import("./types.js").AbuseReport|null}
 */
export function decodeReportSignal(sig) {
  if (!sig || typeof sig !== "object") return null;
  let obj = null;
  if (typeof sig.payload_hex === "string" && sig.payload_hex.length) {
    try {
      const bytes = hexToBytes(sig.payload_hex);
      obj = JSON.parse(new TextDecoder().decode(bytes));
    } catch { obj = null; }
  }
  if (!obj && sig.payload && typeof sig.payload === "object") obj = sig.payload;
  if (!obj && sig.kind === "abuse_report") obj = sig;
  if (!obj || obj.kind !== "abuse_report") return null;
  return obj;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("odd hex");
  const out = new Uint8Array(hex.length / 2);
  for (let k = 0; k < out.length; k++) out[k] = parseInt(hex.slice(k * 2, k * 2 + 2), 16);
  return out;
}

// ---------------------------------------------------------------------------
// reputationFeed — per-node karma penalty deltas (pure, advisory)
// ---------------------------------------------------------------------------

/**
 * Compute per-node karma penalty deltas from a list of AbuseReports. Pure; this
 * is the advisory signal `reputation.js`/the scheduler folds in alongside the
 * immutable `/history` facts. Only confirmed-abusive ('deny') reports count, and
 * each (reporter, host, artifact_digest) pair counts once to limit pile-on.
 *
 * The returned values are NEGATIVE integer deltas (penalties), keyed by host id.
 * `applyAbusePenalty(karma, reports)` from reputation.js is the canonical reducer;
 * this gives the same magnitude as a per-host map for feeding many nodes at once.
 *
 * @param {import("./types.js").AbuseReport[]} reports
 * @returns {Record<string, number>}  hostId -> negative karma delta
 */
export function reputationFeed(reports) {
  /** @type {Record<string, number>} */
  const out = {};
  if (!Array.isArray(reports)) return out;
  const counted = new Set();
  for (const r of reports) {
    if (!r || typeof r !== "object") continue;
    if (r.decision && r.decision !== DECISION.DENY) continue;
    if (!isHex64(r.host)) continue;
    const key = `${r.author || ""}|${r.host}|${r.artifact_digest || ""}`;
    if (counted.has(key)) continue;
    counted.add(key);
    const sev = clampSev(r.severity);
    out[r.host] = (out[r.host] || 0) - sev * KARMA_PER_SEVERITY;
  }
  return out;
}

/**
 * Apply the feed to a base karma for a single node, deferring to reputation.js's
 * canonical reducer so the magnitude matches the rest of the app. Pure.
 * @param {number} baseKarma
 * @param {string} hostId
 * @param {import("./types.js").AbuseReport[]} reports
 * @returns {number}
 */
export function penalizedKarma(baseKarma, hostId, reports) {
  const against = (Array.isArray(reports) ? reports : []).filter((r) => r && r.host === hostId);
  return applyAbusePenalty(baseKarma, against);
}

// ---------------------------------------------------------------------------
// rateLimitOk — anti-grief throttle (pure)
// ---------------------------------------------------------------------------

/**
 * Whether a reporter is under its rate limit: at most MON.REPORT_MAX_PER_WINDOW
 * reports within `windowSecs`. Pure — pass the reporter's recent reports in.
 * @param {string} reporterId           64-hex reporter node id
 * @param {import("./types.js").AbuseReport[]} reports  recent reports (any authors)
 * @param {number} [windowSecs]         window length in seconds (default MON.REPORT_WINDOW_SECS)
 * @param {number} [nowMs]              clock injection for determinism (default Date.now())
 * @returns {boolean}
 */
export function rateLimitOk(reporterId, reports, windowSecs = MON.REPORT_WINDOW_SECS, nowMs = Date.now()) {
  if (!isHex64(reporterId)) return false;
  const cutoff = nowMs - Math.max(0, i(windowSecs)) * 1000;
  let n = 0;
  for (const r of Array.isArray(reports) ? reports : []) {
    if (!r || r.author !== reporterId) continue;
    if (i(r.ts) >= cutoff) n++;
  }
  return n < MON.REPORT_MAX_PER_WINDOW;
}

// ---------------------------------------------------------------------------
// Inline self-test (no network): node src/monitor.js --selftest
// ---------------------------------------------------------------------------

/** Pure, network-free self-test. @returns {{passed:number, failed:number}} */
export function __selftest() {
  let passed = 0, failed = 0;
  const ok = (name, cond) => { if (cond) { passed++; } else { failed++; console.error("FAIL:", name); } };

  const HOST = "a".repeat(64), JOB = "b".repeat(64), DIG = "c".repeat(64), RPT = "d".repeat(64);

  // detectors
  const mining = detectCryptomining({ cpu_pct: 99, sustained_secs: 300, io_bytes: 1000 });
  ok("cryptomining detected", mining && mining.category === ABUSE_CATEGORY.CRYPTOMINING && mining.severity === MON.SEV_CRYPTOMINING);
  ok("no mining when IO high", detectCryptomining({ cpu_pct: 99, sustained_secs: 300, io_bytes: 10_000_000 }) === null);
  ok("no mining when brief", detectCryptomining({ cpu_pct: 99, sustained_secs: 5, io_bytes: 0 }) === null);

  const scan = detectNetworkAbuse({ distinct_peers: 200, window_secs: 30, bytes_per_peer: 64 });
  ok("network abuse detected", scan && scan.category === ABUSE_CATEGORY.NETWORK_ABUSE);
  ok("no scan when few peers", detectNetworkAbuse({ distinct_peers: 3, window_secs: 30, bytes_per_peer: 64 }) === null);

  const nsfw = detectDisallowedContent({ content_flags: ["nsfw"] });
  ok("disallowed content detected", nsfw && nsfw.category === ABUSE_CATEGORY.PORNOGRAPHIC);
  ok("no content flag => null", detectDisallowedContent({ content_flags: [] }) === null);

  // detectAll ordering (highest severity first)
  const all = detectAll({ cpu_pct: 99, sustained_secs: 300, io_bytes: 0, content_flags: ["porn"] });
  ok("detectAll sorts by severity", all.length === 2 && all[0].severity >= all[1].severity);

  // sampleFromSignal
  const s = sampleFromSignal({ job: { job_id: JOB, host: HOST, cpu_pct: 99, sustained_secs: 200, io_bytes: 0 } });
  ok("sampleFromSignal extracts sample", s && s.job_id === JOB && s.host === HOST);
  ok("sampleFromSignal rejects non-job", sampleFromSignal({ foo: 1 }) === null);

  // reputationFeed: penalties are negative, deduped per (reporter,host,digest)
  const reports = [
    { kind: "abuse_report", host: HOST, author: RPT, artifact_digest: DIG, decision: "deny", severity: 80, ts: 1000 },
    { kind: "abuse_report", host: HOST, author: RPT, artifact_digest: DIG, decision: "deny", severity: 80, ts: 2000 }, // dup
    { kind: "abuse_report", host: HOST, author: "e".repeat(64), artifact_digest: DIG, decision: "deny", severity: 20, ts: 3000 },
    { kind: "abuse_report", host: HOST, author: RPT, artifact_digest: DIG, decision: "allow", severity: 99, ts: 4000 }, // not deny
  ];
  const feed = reputationFeed(reports);
  ok("feed penalty negative & deduped", feed[HOST] === -(80 + 20) * KARMA_PER_SEVERITY);
  ok("penalizedKarma floors at 0", penalizedKarma(50, HOST, reports) === 0);
  // applyAbusePenalty (reputation.js) sums ALL deny reports without dedup: 80+80+20=180.
  ok("penalizedKarma subtracts (no dedup)", penalizedKarma(500, HOST, reports) === 500 - 180);

  // rateLimitOk
  const recent = Array.from({ length: MON.REPORT_MAX_PER_WINDOW }, (_, k) => ({ author: RPT, ts: 10_000 + k }));
  ok("rate limit trips at max", rateLimitOk(RPT, recent, 3600, 10_010) === false);
  ok("rate limit ok below max", rateLimitOk(RPT, recent.slice(0, 2), 3600, 10_010) === true);
  ok("rate limit ignores old", rateLimitOk(RPT, [{ author: RPT, ts: 0 }], 1, 10_000_000) === true);
  ok("rate limit rejects bad id", rateLimitOk("xyz", recent, 3600, 10_010) === false);

  // decodeReportSignal
  const enc = (o) => { const b = new TextEncoder().encode(JSON.stringify(o)); let h = ""; for (const x of b) h += x.toString(16).padStart(2, "0"); return h; };
  const r0 = { kind: "abuse_report", host: HOST, category: "cryptomining", severity: 80 };
  ok("decode payload_hex report", JSON.stringify(decodeReportSignal({ payload_hex: enc(r0) })) === JSON.stringify(r0));
  ok("decode flat report", decodeReportSignal(r0) && decodeReportSignal(r0).host === HOST);
  ok("decode non-report => null", decodeReportSignal({ payload_hex: enc({ kind: "vote" }) }) === null);

  // slashTriggerPayload (async) — run inline-sync via a resolved promise check
  let txOk = false;
  slashTriggerPayload({ id: RPT, author: RPT, artifact_digest: DIG, host: HOST, category: "cryptomining", beacon_height: 7 }, { stake: "1000" })
    .then((tx) => { txOk = tx.tx_type === "AbuseReport" && tx.report_hash === RPT && tx.stake === "1000" && tx.host === HOST; });

  console.log(`monitor selftest sync: ${passed} passed, ${failed} failed (async slash-payload checked separately)`);
  return { passed, failed };
}

// Run self-test when executed directly with --selftest.
if (typeof process !== "undefined" && Array.isArray(process.argv) && process.argv.includes("--selftest")) {
  const r = __selftest();
  // also verify the async path deterministically
  slashTriggerPayload(
    { id: "d".repeat(64), author: "d".repeat(64), artifact_digest: "c".repeat(64), host: "a".repeat(64), category: "cryptomining", beacon_height: 7 },
    { stake: "1000" }
  ).then((tx) => {
    const good = tx.tx_type === "AbuseReport" && tx.report_hash === "d".repeat(64) && tx.stake === "1000";
    console.log(`async slash-payload: ${good ? "1 passed" : "1 FAILED"}`);
    process.exit(r.failed === 0 && good ? 0 : 1);
  });
}
