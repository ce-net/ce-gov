// ce-gov operator dashboard — page controller.
//
// Read-only view over the three governance subsystems:
//   1. ACTIVE POLICY SET   (policy.js)  — the enacted rules + Guardian export candidate
//   2. PRE-RUN SCAN LOG    (scan.js)    — cached ScanVerdicts bound to the active policy_set_id
//   3. ABUSE-REPORT FEED   (monitor.js)— signed runtime reports + their karma impact
//
// Pure presentation: all IO goes through a single CeClient; reputation/karma is
// computed from the immutable /history facts via reputation.js, never invented here.
// Money/weights stay decimal strings via Amount; karma/severity are integers.

import { CeClient } from "../src/ce.js";
import {
  KIND,
  DECISION,
  Amount,
  fromHex,
  isValid,
  ScanVerdictSchema,
} from "../src/types.js";
import {
  activePolicySet,
  guardPolicyExport,
  categoryDecision,
} from "../src/policy.js";
import { collectReports, reputationFeed } from "../src/monitor.js";
import {
  profile as repProfile,
  applyAbusePenalty,
} from "../src/reputation.js";

// ---------------------------------------------------------------------------
// Tiny DOM helpers (no framework)
// ---------------------------------------------------------------------------

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const short = (h, n = 10) =>
  typeof h === "string" && h.length > n ? `${h.slice(0, n)}…${h.slice(-4)}` : h || "";
const fmtTs = (ms) => {
  if (!ms) return "";
  try {
    return new Date(ms).toLocaleString(undefined, {
      month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch { return String(ms); }
};
const decision = (d) => (d === DECISION.ALLOW ? "allow" : "deny");

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
  ce: null,
  base: localStorage.getItem("ce-gov.base") || "http://localhost:8844",
  set: null,        // active policy set { id, policies, at_height }
  verdicts: [],     // ScanVerdict[] for current set
  reports: [],      // AbuseReport[]
  karmaCache: new Map(), // hostId -> base karma (int) from /history
  streamHandle: null,
};

// ---------------------------------------------------------------------------
// Scan-verdict collection (no dedicated export; decode signals for current set)
// ---------------------------------------------------------------------------

function decodeScanVerdict(signal) {
  if (!signal || typeof signal.payload_hex !== "string" || !signal.payload_hex.length) return null;
  let obj;
  try {
    obj = JSON.parse(new TextDecoder().decode(fromHex(signal.payload_hex)));
  } catch { return null; }
  if (!obj || obj.kind !== KIND.SCAN_VERDICT) return null;
  if (!isValid(obj, ScanVerdictSchema)) return null;
  return obj;
}

// Collect the latest ScanVerdict per artifact_digest that is bound to the active
// policy_set_id (a policy bump deterministically invalidates stale verdicts).
async function collectVerdicts(ce, policySetId) {
  let signals = [];
  try { signals = await ce.signals(); } catch { return []; }
  if (!Array.isArray(signals)) return [];
  const byDigest = new Map();
  for (const s of signals) {
    const v = decodeScanVerdict(s);
    if (!v) continue;
    if (v.policy_set_id !== policySetId) continue;
    const prev = byDigest.get(v.artifact_digest);
    if (!prev || (v.ts || 0) > (prev.ts || 0)) byDigest.set(v.artifact_digest, v);
  }
  return [...byDigest.values()].sort((a, b) => (b.ts || 0) - (a.ts || 0));
}

// ---------------------------------------------------------------------------
// Karma: base from immutable /history, impact = applyAbusePenalty(base, reports)
// ---------------------------------------------------------------------------

async function baseKarma(hostId) {
  if (state.karmaCache.has(hostId)) return state.karmaCache.get(hostId);
  let k = 0;
  try {
    const p = await repProfile(state.ce, hostId);
    k = p && Number.isInteger(p.karma) ? p.karma : 0;
  } catch { k = 0; }
  state.karmaCache.set(hostId, k);
  return k;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderPolicySet() {
  const setBar = $("#set-bar");
  const list = $("#policy-list");
  setBar.replaceChildren();
  list.replaceChildren();

  const set = state.set;
  if (!set) {
    list.appendChild(el("div", "empty", "No active policy set."));
    $("#policy-count").textContent = "";
    return;
  }

  const mk = (label, valNode) => {
    const span = el("span");
    span.appendChild(el("b", null, label + " "));
    span.appendChild(valNode);
    return span;
  };
  const cid = el("span", "cid", short(set.id, 16));
  cid.title = set.id;
  setBar.appendChild(mk("set", cid));
  setBar.appendChild(mk("policies", document.createTextNode(String(set.policies.length))));
  setBar.appendChild(mk("@height", document.createTextNode(String(set.at_height))));

  $("#policy-count").textContent = `${set.policies.length} rule${set.policies.length === 1 ? "" : "s"}`;

  if (!set.policies.length) {
    list.appendChild(el("div", "empty", "Policy set is empty — no categories governed yet."));
  }
  for (const p of set.policies) {
    const row = el("div", "policy");
    const top = el("div", "top");
    top.appendChild(el("span", `badge ${decision(p.action)}`, p.action));
    top.appendChild(el("span", "cat", p.category));
    if (p.title) top.appendChild(el("span", "title", p.title));
    row.appendChild(top);
    if (p.description) row.appendChild(el("div", "desc", p.description));
    const meta = el("div", "meta");
    const bits = [`state=${p.state}`, `ts=${fmtTs(p.ts)}`];
    if (p.verdict_id) bits.push(`verdict=${short(p.verdict_id, 8)}`);
    bits.push(`by ${short(p.author, 8)}`);
    meta.textContent = bits.join("  ·  ");
    if (p.id) meta.title = `policy id ${p.id}`;
    row.appendChild(meta);
    list.appendChild(row);
  }

  // Guardian export candidate
  const gx = guardPolicyExport(set);
  $("#guard-json").textContent = JSON.stringify(gx, null, 2);
}

function renderScans() {
  const list = $("#scan-list");
  list.replaceChildren();
  $("#scan-count").textContent = state.verdicts.length
    ? `${state.verdicts.length} cached`
    : "";
  if (!state.verdicts.length) {
    list.appendChild(el("div", "empty", "No cached scan verdicts for the active policy set."));
    return;
  }
  for (const v of state.verdicts) {
    const row = el("div", "scan");

    const dcol = el("div", "decision-col");
    dcol.appendChild(el("span", `badge ${decision(v.decision)}`, v.decision));
    dcol.appendChild(el("span", `badge ${v.deterministic ? "det" : "ai"}`, v.deterministic ? "rule" : "ai"));
    row.appendChild(dcol);

    const digest = el("div", "digest", short(v.artifact_digest, 14));
    digest.title = `artifact_digest ${v.artifact_digest}`;
    row.appendChild(digest);

    if (Array.isArray(v.categories) && v.categories.length) {
      row.appendChild(el("div", "cats", v.categories.join(", ")));
    }
    if (v.rationale) row.appendChild(el("div", "rationale", v.rationale));

    const right = el("div", "right-col");
    right.appendChild(el("div", null, `${v.confidence | 0}% conf`));
    const bar = el("div", "conf-bar");
    const fill = el("span");
    fill.style.width = `${Math.max(0, Math.min(100, v.confidence | 0))}%`;
    bar.appendChild(fill);
    right.appendChild(bar);
    if (v.model_id) {
      const m = el("div", null, short(v.model_id, 18));
      m.title = v.model_id;
      right.appendChild(m);
    }
    right.appendChild(el("div", null, fmtTs(v.ts)));
    row.appendChild(right);

    list.appendChild(row);
  }
}

async function renderReports() {
  const list = $("#report-list");
  list.replaceChildren();
  $("#report-count").textContent = state.reports.length
    ? `${state.reports.length} report${state.reports.length === 1 ? "" : "s"}`
    : "";
  if (!state.reports.length) {
    list.appendChild(el("div", "empty", "No abuse reports in the signal window."));
    return;
  }

  // per-host penalty deltas (advisory, deduped) for the impact column
  const feed = reputationFeed(state.reports);

  for (const r of state.reports) {
    const row = el("div", "report");

    const governed = state.set
      ? categoryDecision(state.set, r.category) === DECISION.DENY
      : false;
    if (!governed) row.classList.add("ungoverned");

    const top = el("div", "top");
    top.appendChild(el("span", `badge ${decision(r.decision)}`, r.decision));
    top.appendChild(el("span", "category", r.category));
    if (!governed) {
      const ng = el("span", "badge neutral", "ungoverned");
      ng.title = "category not in the active policy set — report carries no policy authority";
      top.appendChild(ng);
    }
    top.appendChild(el("span", "sev", `sev ${r.severity | 0}/100`));
    row.appendChild(top);

    const host = el("div", "host");
    host.textContent = `host ${short(r.host, 12)}`;
    host.title = `host ${r.host}`;
    row.appendChild(host);

    if (r.evidence) row.appendChild(el("div", "evidence", r.evidence));

    const meta = el("div", "meta");
    const bits = [`job ${short(r.job_id, 8)}`, `digest ${short(r.artifact_digest, 8)}`];
    if (r.validator_verdict_id) bits.push(`ai=${short(r.validator_verdict_id, 8)}`);
    bits.push(`beacon@${r.beacon_height}`);
    bits.push(`by ${short(r.author, 8)}`);
    bits.push(fmtTs(r.ts));
    meta.textContent = bits.join("  ·  ");
    row.appendChild(meta);

    // karma impact: base (from immutable /history) -> penalized
    const base = await baseKarma(r.host);
    const penalized = applyAbusePenalty(base, state.reports.filter((x) => x.host === r.host));
    const delta = penalized - base;
    const k = el("div", "karma");
    if (delta < 0) {
      k.appendChild(el("span", "from", `karma ${base}`));
      k.appendChild(el("span", "arrow", "→"));
      k.appendChild(el("span", "to", String(penalized)));
      k.appendChild(el("span", "delta", ` (${delta})`));
      const f = feed[r.host];
      if (typeof f === "number") k.title = `feed delta for host: ${f}`;
    } else {
      k.appendChild(el("span", "none", `karma ${base} — no penalty applied`));
    }
    row.appendChild(k);

    list.appendChild(row);
  }
}

// ---------------------------------------------------------------------------
// Load + refresh
// ---------------------------------------------------------------------------

function setStatus(kind, text) {
  const dot = $("#conn-dot");
  dot.className = `dot ${kind}`;
  $("#conn-text").textContent = text;
}

function showError(msg) {
  const b = $("#err");
  if (!msg) { b.classList.remove("show"); b.textContent = ""; return; }
  b.textContent = msg;
  b.classList.add("show");
}

async function refresh() {
  showError("");
  setStatus("", "loading…");
  try {
    const ce = state.ce;
    // status (height) + active set
    let height = "?";
    try { const st = await ce.status(); height = st && st.height != null ? st.height : "?"; } catch {}
    state.set = await activePolicySet(ce);
    state.karmaCache.clear();
    const [verdicts, reports] = await Promise.all([
      collectVerdicts(ce, state.set.id),
      collectReports(ce),
    ]);
    state.verdicts = verdicts;
    state.reports = reports.sort((a, b) => (b.ts || 0) - (a.ts || 0));

    renderPolicySet();
    renderScans();
    await renderReports();

    $("#foot").textContent =
      `node ${state.base}  ·  height ${height}  ·  refreshed ${fmtTs(Date.now())}`;
    setStatus("ok", "connected");
  } catch (e) {
    setStatus("err", "error");
    showError(`Failed to load from ${state.base}: ${e && e.message ? e.message : e}`);
  }
}

function connect() {
  if (state.streamHandle) { try { state.streamHandle.close(); } catch {} state.streamHandle = null; }
  state.ce = new CeClient({ base: state.base, fetch: window.fetch.bind(window) });
  $("#base-input").value = state.base;
  refresh();

  // live: any new signal may be a scan verdict / abuse report / policy enact.
  // Debounce a full refresh so the three panels stay coherent against one set id.
  let timer = null;
  try {
    state.streamHandle = state.ce.signalsStream(
      () => {
        setStatus("live", "live");
        if (timer) clearTimeout(timer);
        timer = setTimeout(refresh, 600);
      },
      () => {}, // SSE errors are non-fatal; polling fallback covers it
    );
  } catch { /* no SSE; rely on manual + interval refresh */ }
}

// ---------------------------------------------------------------------------
// Wire up
// ---------------------------------------------------------------------------

function init() {
  $("#refresh-btn").addEventListener("click", refresh);
  $("#connect-btn").addEventListener("click", () => {
    const v = $("#base-input").value.trim().replace(/\/+$/, "");
    if (!v) return;
    state.base = v;
    localStorage.setItem("ce-gov.base", v);
    connect();
  });
  $("#base-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#connect-btn").click();
  });
  $("#copy-guard").addEventListener("click", async () => {
    const txt = $("#guard-json").textContent || "";
    try { await navigator.clipboard.writeText(txt); $("#copy-guard").textContent = "copied"; }
    catch { $("#copy-guard").textContent = "copy failed"; }
    setTimeout(() => { $("#copy-guard").textContent = "copy"; }, 1500);
  });

  // periodic refresh as a safety net if SSE is unavailable
  setInterval(() => { if (document.visibilityState === "visible") refresh(); }, 30000);

  connect();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
