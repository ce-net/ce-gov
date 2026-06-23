// @ce-net/gov — reputation.js
//
// Shared karma / expertise engine. CE gives immutable FACTS about a node via
// GET /history/:node_id (NodeStats). There is NO karma number on-chain by
// design — apps compute it. This module turns those facts into:
//
//   * an integer `karma` scalar (general reputation),
//   * a per-domain `expertise` map (who may submit expert arguments),
//   * a `rawWeight` base-unit amount string consumed by voting.js (pre-quadratic;
//     voting.js applies the sqrt/quadratic Sybil damping on top).
//
// DESIGN ALIGNMENT (CE consensus weight oracle, docs/consensus.md §2 / sybil-resistance.md):
//   The on-chain consensus weight is W = min(active_bond, earned_work_score). We mirror that
//   coupling in `rawWeight`: reputation weight is anchored to *settled, burned, earned work*
//   (`earned`), not to claimed activity, and is zeroed/penalized by slashes. Quadratic damping is
//   deliberately NOT applied here — that is voting.js's job (`quadWeight`) so the raw, auditable
//   weight stays linear and explainable, and a single damping point avoids double-discounting.
//
// PURITY: every scoring function is pure and takes plain NodeStats (or a profile) so voting.js /
// monitor.js can call it without re-fetching. The only IO is `profile()`, which goes through an
// injected CeClient and is wrapped in a tiny TTL cache.
//
// MONEY: `earned`/`recent_earned` are base-unit decimal strings — handled via `Amount`/BigInt,
// never floats. Scores (karma, expertise, severity) are plain integers, NOT money.

import { Amount, makeNodeProfileLite } from "./types.js";

// ---------------------------------------------------------------------------
// Tunable constants (documented; integer-only so results are deterministic)
// ---------------------------------------------------------------------------

/**
 * Scoring constants. All public so callers/tests can reason about thresholds.
 * Karma is an unbounded non-negative integer; expertise scores are 0..100-ish
 * integers (not hard-clamped, but normalized toward that range).
 */
export const REP = Object.freeze({
  // 1 credit of *earned* work ≈ this many karma points. We score per-credit so a
  // node that has earned 5 credits gets 5 * EARNED_KARMA_PER_CREDIT base karma.
  EARNED_KARMA_PER_CREDIT: 10,
  // each successfully hosted job is worth this many karma points (liveness signal).
  KARMA_PER_JOB: 1,
  // each hosted heartbeat (long-running cell uptime) is a small liveness signal.
  KARMA_PER_HEARTBEAT: 0,
  // a slash is a proven protocol violation: it zeroes weight on-chain. We make it
  // brutal here too — each slash multiplies remaining karma down hard.
  SLASH_PENALTY_PER: 100, // flat points removed per slash (in addition to the multiplier)
  SLASH_MULT_NUM: 1, // remaining karma *= SLASH_MULT_NUM / SLASH_MULT_DEN per slash
  SLASH_MULT_DEN: 4,
  // an expiry (host took escrow then failed to deliver) is a soft fault, not proven
  // malice — a smaller linear penalty.
  EXPIRY_PENALTY_PER: 5,
  // recency: a node whose *recent* earned work is high is up-weighted vs. a node
  // coasting on ancient history. recent_earned contributes at this multiple.
  RECENCY_KARMA_PER_CREDIT: 5,
  // expertise: per matching-tag job/earn contribution. Expertise is bounded toward
  // 0..100 via a saturating log-ish step (see expertiseFor).
  EXPERTISE_CAP: 100,
  // abuse-report down-weighting (monitor.js feed). Each unit of summed severity
  // removes this many karma points (severity is 0..100 per report).
  ABUSE_KARMA_PER_SEVERITY: 1,
  // rawWeight is anchored to min(earned, recent-amplified earned) so a node cannot
  // mint weight purely from old history; mirrors min(bond, work). This is the
  // fraction (num/den) of `earned` that recent activity must back to count fully.
  RAW_RECENT_NUM: 1,
  RAW_RECENT_DEN: 1,
});

// ---------------------------------------------------------------------------
// NodeStats normalization
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} NodeStats
 * @property {number} [jobs_hosted]
 * @property {string} [earned]          base-unit decimal string
 * @property {string} [spent]           base-unit decimal string
 * @property {string} [recent_earned]   windowed, base-unit decimal string
 * @property {string} [recent_spent]    windowed, base-unit decimal string
 * @property {number} [slashes]
 * @property {number} [expiries]
 * @property {number} [heartbeats_hosted]
 * @property {Object<string,number>} [tag_jobs]   optional per-tag job counts (if the node exposes them)
 * @property {Object<string,string>} [tag_earned] optional per-tag earned amounts (base-unit strings)
 */

/** A safe non-negative integer from any input. @param {*} v @returns {number} */
function int(v) {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return 0;
  const i = Math.trunc(n);
  return i < 0 ? 0 : i;
}

/** A base-unit BigInt from a stats field, defaulting to 0n; clamps negatives to 0. */
function amt(v) {
  if (v === undefined || v === null) return 0n;
  let b;
  try {
    b = typeof v === "bigint" ? v : Amount.toBig(String(v));
  } catch {
    return 0n;
  }
  return b < 0n ? 0n : b;
}

/**
 * Normalize an arbitrary /history response (or a NodeProfileLite) into the plain
 * stats fields the pure scorers expect. Accepts a raw NodeStats or a profile.
 * @param {NodeStats|object} s
 * @returns {{jobs_hosted:number, slashes:number, expiries:number, heartbeats_hosted:number,
 *            earned:bigint, recent_earned:bigint, spent:bigint, tag_jobs:object, tag_earned:object}}
 */
function norm(s) {
  s = s || {};
  return {
    jobs_hosted: int(s.jobs_hosted),
    slashes: int(s.slashes),
    expiries: int(s.expiries),
    heartbeats_hosted: int(s.heartbeats_hosted ?? s.heartbeats),
    earned: amt(s.earned),
    recent_earned: amt(s.recent_earned),
    spent: amt(s.spent),
    tag_jobs: (s.tag_jobs && typeof s.tag_jobs === "object") ? s.tag_jobs : {},
    tag_earned: (s.tag_earned && typeof s.tag_earned === "object") ? s.tag_earned : {},
  };
}

/** Integer credits (floored) from a base-unit BigInt. */
function creditsFloor(baseUnits) {
  return Number(baseUnits / 1_000_000_000_000_000_000n);
}

// ---------------------------------------------------------------------------
// Pure scorers
// ---------------------------------------------------------------------------

/**
 * Compute an integer karma score from NodeStats.
 *
 * karma = earned-work + liveness + recency, then slash/expiry-penalized.
 * Earned work dominates (it is the burned, settled, hard-to-fake signal); slashes
 * crater the score (mirrors the on-chain "a fully-slashed node has W=0").
 *
 * Pure. Never returns < 0.
 * @param {NodeStats} stats
 * @returns {number}
 */
export function computeKarma(stats) {
  const s = norm(stats);

  // Base: earned credits dominate; liveness (jobs/heartbeats) adds a smaller term.
  let karma =
    creditsFloor(s.earned) * REP.EARNED_KARMA_PER_CREDIT +
    creditsFloor(s.recent_earned) * REP.RECENCY_KARMA_PER_CREDIT +
    s.jobs_hosted * REP.KARMA_PER_JOB +
    s.heartbeats_hosted * REP.KARMA_PER_HEARTBEAT;

  // Soft fault: expiries (took escrow, failed to deliver) — linear penalty.
  karma -= s.expiries * REP.EXPIRY_PENALTY_PER;

  // Hard fault: each slash applies a flat removal AND a multiplicative haircut.
  if (s.slashes > 0) {
    karma -= s.slashes * REP.SLASH_PENALTY_PER;
    // multiplicative: karma *= (num/den)^slashes, integer-only, capped iterations.
    const iters = Math.min(s.slashes, 16);
    for (let i = 0; i < iters; i++) {
      karma = Math.trunc((karma * REP.SLASH_MULT_NUM) / REP.SLASH_MULT_DEN);
    }
  }

  return karma < 0 ? 0 : Math.trunc(karma);
}

/**
 * Compute per-tag integer expertise scores. Expertise reflects *demonstrated work
 * in a domain*. If the node exposes per-tag breakdowns (tag_jobs / tag_earned) we
 * use them; otherwise we derive a proxy from overall karma so the node still has a
 * (lower) baseline expertise in any requested tag. Saturating toward EXPERTISE_CAP
 * so a whale can't claim infinite domain authority.
 *
 * Pure. Returns a Record<tag, int>.
 * @param {NodeStats} stats
 * @param {string[]} tags
 * @returns {Record<string, number>}
 */
export function expertiseFor(stats, tags) {
  const s = norm(stats);
  const out = {};
  if (!Array.isArray(tags) || tags.length === 0) return out;

  const baseKarma = computeKarma(stats);
  // Proxy baseline: log-ish saturating function of general karma (no tag-specific data).
  const baseProxy = satScore(baseKarma);

  for (const rawTag of tags) {
    const tag = String(rawTag);
    let score;
    const hasTagData =
      Object.prototype.hasOwnProperty.call(s.tag_jobs, tag) ||
      Object.prototype.hasOwnProperty.call(s.tag_earned, tag);

    if (hasTagData) {
      const tagJobs = int(s.tag_jobs[tag]);
      const tagEarnedCredits = creditsFloor(amt(s.tag_earned[tag]));
      // tag-specific signal: earned-in-domain dominates, jobs-in-domain add.
      score = satScore(tagEarnedCredits * REP.EARNED_KARMA_PER_CREDIT + tagJobs * 5);
    } else {
      // no per-tag breakdown: discount the general proxy (you're not a proven expert
      // in *this* domain specifically — half credit).
      score = Math.trunc(baseProxy / 2);
    }
    out[tag] = Math.min(REP.EXPERTISE_CAP, Math.max(0, score));
  }
  return out;
}

/**
 * Saturating integer score: maps an unbounded non-negative input toward 0..CAP.
 * Uses an integer log2-ish curve (each doubling adds ~CAP/14 points) so early work
 * counts a lot and additional work has diminishing returns — caps whale dominance.
 * Pure, deterministic, integer-only.
 * @param {number} x
 * @returns {number}
 */
export function satScore(x) {
  const n = int(x);
  if (n <= 0) return 0;
  // bit length of n ≈ floor(log2(n)) + 1, in [1..~53] for reasonable inputs.
  let bits = 0;
  let v = n;
  while (v > 0) { bits++; v = Math.floor(v / 2); }
  // each bit ≈ EXPERTISE_CAP/14 ; saturates around 2^14 input.
  const score = Math.trunc((bits * REP.EXPERTISE_CAP) / 14);
  return Math.min(REP.EXPERTISE_CAP, score);
}

/**
 * The RAW reputation weight (pre-quadratic) as a base-unit decimal string,
 * consumed by voting.js (which then applies `quadWeight` sqrt damping).
 *
 * Anchored to settled earned work, coupled to recent activity (mirrors
 * `min(bond, earned-work)`): a node cannot vote with weight it earned long ago if
 * it has gone dark — the effective earned figure is pulled toward recent_earned.
 * Slashes zero it; expiries discount it. If expert tags are supplied, the weight
 * is scaled by the node's mean expertise in those tags (a domain-irrelevant whale
 * gets less say on a specialist proposal).
 *
 * Pure (accepts either a profile or raw stats). Returns an Amount string.
 * @param {NodeProfileLite|NodeStats} profileOrStats
 * @param {string[]} [expertiseTags]
 * @returns {string} base-unit decimal string
 */
export function rawWeight(profileOrStats, expertiseTags) {
  const s = norm(profileOrStats);

  // A slashed node has zero weight, full stop (mirrors on-chain W=0).
  if (s.slashes > 0) return "0";

  // Effective earned = earned, but coupled to recent activity so dormant earned
  // weight decays. eff = min(earned, recent_earned * RAW_RECENT_DEN/RAW_RECENT_NUM)
  // when recent is the binding (smaller) signal; otherwise earned stands.
  const recentScaled =
    (s.recent_earned * BigInt(REP.RAW_RECENT_DEN)) / BigInt(REP.RAW_RECENT_NUM);
  // Coupling: take the *larger* of "recent" and a floor of earned/4, but never above
  // earned. This keeps a steady long-term contributor from being zeroed by one quiet
  // window, while still rewarding recency.
  const floorEarned = s.earned / 4n;
  let eff = recentScaled > floorEarned ? recentScaled : floorEarned;
  if (eff > s.earned) eff = s.earned;

  // Expiry discount: each expiry removes 1/16 of the effective weight, floored at 0.
  if (s.expiries > 0) {
    const keepNum = BigInt(Math.max(0, 16 - s.expiries));
    eff = (eff * keepNum) / 16n;
  }

  // Expertise scaling: scale by mean expertise/CAP over the requested tags.
  if (Array.isArray(expertiseTags) && expertiseTags.length > 0) {
    const exMap =
      (profileOrStats && profileOrStats.expertise && typeof profileOrStats.expertise === "object")
        ? profileOrStats.expertise
        : expertiseFor(profileOrStats, expertiseTags);
    let sum = 0;
    for (const t of expertiseTags) sum += int(exMap[String(t)]);
    const mean = Math.trunc(sum / expertiseTags.length); // 0..CAP
    eff = (eff * BigInt(mean)) / BigInt(REP.EXPERTISE_CAP);
  }

  return Amount.fromBig(eff < 0n ? 0n : eff);
}

/**
 * Down-weight a karma score by signed AbuseReports (the monitor.js feed). Pure.
 * Sums report severities (0..100 each) and removes ABUSE_KARMA_PER_SEVERITY karma
 * per severity point, floored at 0. Reports without a `severity` count as 0; the
 * caller (monitor.js) is responsible for dedup / rate-limit / signature checks —
 * this function just applies whatever it's given.
 * @param {number} karma
 * @param {import("./types.js").AbuseReport[]} reports
 * @returns {number}
 */
export function applyAbusePenalty(karma, reports) {
  let k = int(karma);
  if (!Array.isArray(reports)) return k;
  let sev = 0;
  for (const r of reports) {
    if (!r || typeof r !== "object") continue;
    // only count 'deny' (confirmed-abusive) reports as penalties.
    if (r.decision && r.decision !== "deny") continue;
    sev += Math.max(0, Math.min(100, int(r.severity)));
  }
  k -= sev * REP.ABUSE_KARMA_PER_SEVERITY;
  return k < 0 ? 0 : k;
}

// ---------------------------------------------------------------------------
// Expertise gating helper (who may submit expert arguments)
// ---------------------------------------------------------------------------

/** Default minimum mean expertise required to submit an expert argument. */
export const EXPERT_ARG_THRESHOLD = 30;

/**
 * Whether a node qualifies as an "expert" for a proposal's expertise tags, i.e.
 * may have its argument weighted as expert testimony. Pure.
 * @param {NodeProfileLite|NodeStats} profileOrStats
 * @param {string[]} tags
 * @param {number} [threshold]
 * @returns {boolean}
 */
export function isExpert(profileOrStats, tags, threshold = EXPERT_ARG_THRESHOLD) {
  if (!Array.isArray(tags) || tags.length === 0) return true; // no tags => no gate
  const exMap =
    (profileOrStats && profileOrStats.expertise && typeof profileOrStats.expertise === "object")
      ? profileOrStats.expertise
      : expertiseFor(profileOrStats, tags);
  let sum = 0;
  for (const t of tags) sum += int(exMap[String(t)]);
  return Math.trunc(sum / tags.length) >= threshold;
}

// ---------------------------------------------------------------------------
// profile() — the only IO; cached over ce.history
// ---------------------------------------------------------------------------

const DEFAULT_TTL_MS = 30_000;
/** @type {Map<string,{at:number, value:import("./types.js").NodeProfileLite}>} */
const _cache = new Map();

/** Clear the profile cache (tests / forced refresh). */
export function clearProfileCache() { _cache.clear(); }

/**
 * Fetch /history/:nodeId, compute karma + expertise (+ carry raw NodeStats fields),
 * and return a schema-valid NodeProfileLite. Cached with a short TTL keyed by
 * (nodeId, sorted tags) so repeated voting/tally lookups don't hammer the node.
 *
 * IO is dependency-injected via the passed CeClient. `at_height` provenance comes
 * from ce.status() (best-effort; 0 if unavailable).
 *
 * @param {import("./ce.js").CeClient} ce
 * @param {string} nodeId  64-hex
 * @param {Object} [opts]
 * @param {string[]} [opts.tags]    expertise tags to compute (default [])
 * @param {number} [opts.ttlMs]     cache TTL (default 30s; 0 disables caching)
 * @returns {Promise<import("./types.js").NodeProfileLite>}
 */
export async function profile(ce, nodeId, opts = {}) {
  const tags = Array.isArray(opts.tags) ? opts.tags.map(String) : [];
  const ttl = opts.ttlMs ?? DEFAULT_TTL_MS;
  const key = `${nodeId}|${[...tags].sort().join(",")}`;

  if (ttl > 0) {
    const hit = _cache.get(key);
    if (hit && Date.now() - hit.at < ttl) return hit.value;
  }

  let stats = {};
  try {
    stats = (await ce.history(nodeId)) || {};
  } catch {
    // Graceful degrade: unknown node => zero-stats profile (karma 0, weight 0).
    stats = {};
  }

  let at_height = 0;
  try {
    const st = await ce.status();
    at_height = int(st && st.height);
  } catch {
    at_height = 0;
  }

  const value = profileFromStats(nodeId, stats, tags, at_height);
  if (ttl > 0) _cache.set(key, { at: Date.now(), value });
  return value;
}

/**
 * Pure: build a NodeProfileLite from already-fetched stats (no IO). Useful for
 * tests and for callers that already have /history data.
 * @param {string} nodeId
 * @param {NodeStats} stats
 * @param {string[]} [tags]
 * @param {number} [at_height]
 * @returns {import("./types.js").NodeProfileLite}
 */
export function profileFromStats(nodeId, stats, tags = [], at_height = 0) {
  const s = norm(stats);
  return makeNodeProfileLite({
    node_id: nodeId,
    karma: computeKarma(stats),
    expertise: expertiseFor(stats, tags),
    earned: Amount.fromBig(s.earned),
    recent_earned: Amount.fromBig(s.recent_earned),
    jobs_hosted: s.jobs_hosted,
    slashes: s.slashes,
    expiries: s.expiries,
    at_height: int(at_height),
  });
}

// ---------------------------------------------------------------------------
// Inline self-test (no network) — run: `node src/reputation.js`
// ---------------------------------------------------------------------------

/**
 * Pure self-test. Returns { ok, checks }. Exported so a harness can call it; also
 * auto-runs when this file is executed directly.
 */
export function __selftest() {
  const checks = [];
  const eq = (name, got, want) => checks.push({ name, ok: JSON.stringify(got) === JSON.stringify(want), got, want });
  const ok = (name, cond) => checks.push({ name, ok: !!cond });

  const C = 1_000_000_000_000_000_000n;

  // a solid contributor: 5 credits earned, 2 recent, 12 jobs, no faults
  const good = {
    earned: (5n * C).toString(),
    recent_earned: (2n * C).toString(),
    jobs_hosted: 12,
    heartbeats_hosted: 30,
    slashes: 0,
    expiries: 0,
  };
  const kGood = computeKarma(good);
  ok("good karma > 0", kGood > 0);
  // 5*10 + 2*5 + 12*1 = 50 + 10 + 12 = 72
  eq("good karma value", kGood, 72);

  // slashing craters karma to 0-ish
  const slashed = { ...good, slashes: 2 };
  const kSlashed = computeKarma(slashed);
  ok("slashed karma << good karma", kSlashed < kGood);
  eq("slashed rawWeight is 0", rawWeight(slashed), "0");

  // expiries reduce karma but don't zero it
  const expired = { ...good, expiries: 3 };
  ok("expiry penalty applied", computeKarma(expired) === kGood - 15);

  // rawWeight: anchored to earned, coupled to recent. recent(2C) > earned/4(1.25C) => eff=2C
  eq("rawWeight good", rawWeight(good), (2n * C).toString());

  // dormant node: earned high, recent 0 => eff = earned/4
  const dormant = { earned: (8n * C).toString(), recent_earned: "0", jobs_hosted: 5 };
  eq("rawWeight dormant = earned/4", rawWeight(dormant), (2n * C).toString());

  // rawWeight never exceeds earned
  const surge = { earned: (1n * C).toString(), recent_earned: (100n * C).toString() };
  eq("rawWeight capped at earned", rawWeight(surge), (1n * C).toString());

  // expertise: saturating, bounded by cap
  const ex = expertiseFor(good, ["security", "legal"]);
  ok("expertise has both tags", "security" in ex && "legal" in ex);
  ok("expertise within cap", ex.security >= 0 && ex.security <= REP.EXPERTISE_CAP);

  // tag-specific data beats the generic proxy
  const specialist = { ...good, tag_jobs: { security: 40 }, tag_earned: { security: (20n * C).toString() } };
  const exSpec = expertiseFor(specialist, ["security", "legal"]);
  ok("specialist > generalist in domain", exSpec.security >= ex.security);
  ok("specialist weak in off-domain", exSpec.legal <= exSpec.security);

  // isExpert gating
  ok("specialist is expert in security", isExpert(specialist, ["security"]));
  ok("empty tags => no gate", isExpert({}, []) === true);

  // expertise scaling in rawWeight: irrelevant tags shrink weight
  const wPlain = rawWeight(good);
  const wTagged = rawWeight(good, ["security", "legal"]);
  ok("tagged weight <= plain weight", BigInt(wTagged) <= BigInt(wPlain));

  // abuse penalty
  const reports = [
    { decision: "deny", severity: 30 },
    { decision: "deny", severity: 20 },
    { decision: "allow", severity: 90 }, // not counted
  ];
  eq("abuse penalty subtracts 50", applyAbusePenalty(100, reports), 50);
  eq("abuse penalty floors at 0", applyAbusePenalty(10, reports), 0);

  // profileFromStats produces a schema-valid NodeProfileLite
  const prof = profileFromStats("a".repeat(64), good, ["security"], 1234);
  ok("profile node_id", prof.node_id === "a".repeat(64));
  ok("profile karma matches", prof.karma === kGood);
  ok("profile earned is string", typeof prof.earned === "string");
  ok("profile at_height", prof.at_height === 1234);

  // satScore monotonic-ish & bounded
  ok("satScore(0)=0", satScore(0) === 0);
  ok("satScore bounded", satScore(1 << 30) <= REP.EXPERTISE_CAP);
  ok("satScore monotonic", satScore(1000) >= satScore(10));

  const allOk = checks.every((c) => c.ok);
  return { ok: allOk, checks };
}

// Auto-run when executed directly (Node ESM entrypoint detection, no network).
if (typeof process !== "undefined" && process.argv && process.argv[1]) {
  const here = new URL("", import.meta.url).pathname;
  if (process.argv[1] === here || process.argv[1].endsWith("/reputation.js")) {
    const { ok, checks } = __selftest();
    for (const c of checks) {
      // eslint-disable-next-line no-console
      console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}` + (c.ok ? "" : `  got=${JSON.stringify(c.got)} want=${JSON.stringify(c.want)}`));
    }
    // eslint-disable-next-line no-console
    console.log(ok ? "\nreputation.js self-test: ALL PASS" : "\nreputation.js self-test: FAILURES");
    if (!ok) process.exitCode = 1;
  }
}
