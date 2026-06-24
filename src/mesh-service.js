// @ce-net/gov — the node-side GOVERNANCE BACKEND as a real mesh service.
//
// This is the long-running component that turns a node into a governance participant on
// the mesh. It owns NO central state and runs NO app HTTP server — everything rides the
// LOCAL node's verified mesh primitives (src/mesh.js / src/ce.js):
//
//   * ADVERTISE  — `GOV_SERVICE` (generic index/get) AND `GOV_VALIDATOR_SERVICE`
//                  ("gov/validator") in the DHT, with a re-advertise loop (records expire).
//   * SUBSCRIBE  — `GOV_TOPIC`, plus the scoped `gov/proposals` / `gov/votes` topics, and
//                  consume the single inbound `/mesh/messages/stream`.
//   * INDEX      — rebuild a local id->cid index from announced event CIDs (pubsub). The
//                  blob store is the source of truth; the index is a cache/catalog.
//   * SERVE      — on an inbound REQUEST (an AppMessage carrying a `reply_token`):
//                    op:"index"    -> reply the current index
//                    op:"get"      -> reply the artifact JSON for a cid (from blobs)
//                    op:"validate" -> run validator.js (+ reputation.js) and reply a verdict
//   * PERSIST    — proposals/arguments/verdicts are stored as content-addressed BLOBS by the
//                  producing modules (proposals.js / voting.js / policy.js); this service
//                  re-announces their CIDs and answers catch-up queries for them.
//
// It reuses the existing modules unchanged: validator.validateArgument + reputation.profile
// for the "validate" query; proposals/voting/policy already write blobs and (now) announce.
// Wiring them to mesh transport instead of local-only signals is exactly this module's job.
//
// DESIGN RULES: inject the `CeClient`; no host mutation; pure where possible; offline-testable.

import {
  GOV_SERVICE,
  GOV_VALIDATOR_SERVICE,
  GOV_TOPIC,
  TOPIC_PROPOSALS,
  TOPIC_VOTES,
  EV,
  OP,
  encodeJsonHex,
  decodeJsonHex,
  decodeEvent,
} from "./mesh.js";
import { validateArgument } from "./validator.js";
import { profile } from "./reputation.js";

/**
 * @typedef {import("./ce.js").CeClient} CeClient
 * @typedef {{ type:string, id:string, cid:string, height:number }} IndexEvent
 */

const _dec = new TextDecoder();

/** Default re-advertise cadence (DHT records expire; the node docs suggest minutes). */
export const READVERTISE_MS = 10 * 60_000;

/**
 * Start the governance mesh service. Advertises the service names, subscribes to the
 * governance topics, consumes the inbound stream, maintains the local index, and answers
 * `index` / `get` / `validate` requests. Returns a handle:
 *   * `stop()`         — close the stream + stop the re-advertise loop.
 *   * `index()`        — snapshot the current id->event index (array of IndexEvent).
 *   * `validate(arg)`  — run the validator locally (also reachable over the mesh).
 *   * `serviceNames`   — the advertised DHT service names.
 *   * `topics`         — the subscribed pubsub topics.
 *
 * @param {CeClient} ce
 * @param {Object} [opts]
 * @param {import("./validator.js").LlmAdapter} [opts.llm]  shared LLM adapter for validate.
 * @param {(p:string,s:string,a:string)=>(boolean|Promise<boolean>)} [opts.verifySig]
 * @param {(url:string)=>number} [opts.trustOf]   source-trust resolver passed to the validator.
 * @param {number} [opts.readvertiseMs=READVERTISE_MS]
 * @param {(ev:IndexEvent)=>void} [opts.onEvent]  observer hook for inbound index events.
 * @param {(err:Error)=>void} [opts.onErr]
 * @param {boolean} [opts.serveValidate=true]     answer op:"validate" requests.
 * @returns {Promise<{stop:()=>void, index:()=>IndexEvent[], validate:(arg:object)=>Promise<object>, serviceNames:string[], topics:string[]}>}
 */
export async function startGovService(ce, opts = {}) {
  if (!ce) throw new TypeError("startGovService: ce client required");

  const readvertiseMs = opts.readvertiseMs ?? READVERTISE_MS;
  const serviceNames = [GOV_SERVICE, GOV_VALIDATOR_SERVICE];
  const topics = [GOV_TOPIC, TOPIC_PROPOSALS, TOPIC_VOTES];

  /** @type {Map<string, IndexEvent>} id -> latest IndexEvent for it */
  const index = new Map();

  // 1) Subscribe to every governance topic so inbound events arrive on the stream.
  for (const t of topics) {
    try { await ce.meshSubscribe(t); } catch (e) { opts.onErr && opts.onErr(e); }
  }

  // 2) Advertise both service names now, then on an interval (records expire).
  const advertiseAll = async () => {
    for (const s of serviceNames) {
      try { await ce.meshAdvertise(s); } catch (e) { opts.onErr && opts.onErr(e); }
    }
  };
  await advertiseAll();
  let timer = null;
  if (readvertiseMs > 0 && typeof setInterval === "function") {
    timer = setInterval(advertiseAll, readvertiseMs);
    if (timer && typeof timer.unref === "function") timer.unref();
  }

  // The validator the "validate" op runs. Reuses validator.js + reputation.js exactly as
  // the in-process facade does — just reachable over the mesh now.
  async function validate(argument) {
    const v = await validateArgument(argument, {
      llm: opts.llm,
      trustOf: opts.trustOf,
      verifySig: opts.verifySig,
    });
    return v;
  }

  // 3) Consume the single inbound stream: pubsub events update the index; requests are served.
  const handle = ce.meshStream(async (m) => {
    try {
      if (m && m.reply_token != null) {
        await handleRequest(m);
      } else if (m && (m.topic === GOV_TOPIC || m.topic === TOPIC_PROPOSALS || m.topic === TOPIC_VOTES)) {
        const ev = decodeEvent(m);
        if (ev) {
          index.set(ev.id, ev);
          if (opts.onEvent) opts.onEvent(ev);
        }
      }
    } catch (e) {
      opts.onErr && opts.onErr(e);
    }
  }, opts.onErr);

  /**
   * Answer an inbound request. The request topic is the service name; the payload is a
   * `{ op, ... }` envelope. Always replies (even with `{error}`) so the caller's
   * `/mesh/request` doesn't hang to its timeout on a malformed op.
   * @param {{topic:string, payload_hex:string, reply_token:number}} m
   */
  async function handleRequest(m) {
    const req = decodeJsonHex(m.payload_hex) || {};
    let reply;
    try {
      if (req.op === OP.INDEX) {
        reply = { index: [...index.values()] };
      } else if (req.op === OP.GET) {
        reply = { artifact: await getArtifact(ce, req.cid) };
      } else if (req.op === OP.VALIDATE && opts.serveValidate !== false) {
        if (!req.argument || typeof req.argument !== "object") {
          reply = { error: "validate: argument required" };
        } else {
          reply = { validation: await validate(req.argument) };
        }
      } else {
        reply = { error: `unknown op: ${req.op}` };
      }
    } catch (e) {
      reply = { error: String((e && e.message) || e) };
    }
    try {
      await ce.meshReply(m.reply_token, encodeJsonHex(reply));
    } catch (e) {
      opts.onErr && opts.onErr(e);
    }
  }

  return {
    serviceNames,
    topics,
    index: () => [...index.values()],
    validate,
    stop() {
      try { handle.close(); } catch { /* ignore */ }
      if (timer) { try { clearInterval(timer); } catch { /* ignore */ } timer = null; }
    },
  };
}

/**
 * Fetch + parse an artifact JSON blob by cid via the LOCAL node (`/blobs`, DHT-resolving
 * on a miss). Returns the parsed object or null. Used to answer op:"get".
 * @param {CeClient} ce
 * @param {string} cid
 * @returns {Promise<object|null>}
 */
export async function getArtifact(ce, cid) {
  if (!ce || typeof cid !== "string") return null;
  let bytes = null;
  try {
    bytes = ce.meshGetBlob ? await ce.meshGetBlob(cid) : await ce.getBlob(cid);
  } catch {
    return null;
  }
  if (!bytes) return null;
  try {
    return JSON.parse(_dec.decode(bytes));
  } catch {
    return null;
  }
}

/**
 * Query a discovered "gov/validator" peer to validate an argument over the mesh (the
 * request side of op:"validate"). Returns the peer's `ArgumentValidation`, or null if no
 * validator peer answered. A node without the validator stack (e.g. a browser) uses this
 * to borrow a full node's judgment.
 * @param {CeClient} ce
 * @param {object} argument
 * @param {Object} [opts]
 * @param {number} [opts.timeout_ms=20000]
 * @param {number} [opts.maxPeers=3]
 * @returns {Promise<object|null>}
 */
export async function requestValidation(ce, argument, opts = {}) {
  const timeout = opts.timeout_ms ?? 20000;
  let providers = [];
  try {
    const found = await ce.meshFind(GOV_VALIDATOR_SERVICE);
    providers = (found && found.providers) || [];
  } catch {
    return null;
  }
  let selfId = null;
  try { const st = await ce.status(); selfId = st && (st.node_id || st.id); } catch { /* ok */ }
  const ordered = providers.filter((p) => p !== selfId);
  for (const peer of ordered.slice(0, opts.maxPeers ?? 3)) {
    try {
      const r = await ce.meshRequest(peer, GOV_VALIDATOR_SERVICE, encodeJsonHex({ op: OP.VALIDATE, argument }), timeout);
      const body = decodeJsonHex(r && r.payload_hex);
      if (body && body.validation) return body.validation;
      if (body && body.error) continue;
    } catch {
      /* next peer */
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Self-test (no network) — run with: node src/mesh-service.js
// ---------------------------------------------------------------------------

/**
 * Offline self-test: stand up a service node A over the in-memory fake mesh, announce a
 * proposal + an argument, and from node B (1) catch up via an op:"index" request, (2) pull
 * an artifact via op:"get", and (3) validate an argument via op:"validate". No network.
 * @returns {Promise<number>} assertions passed
 */
export async function __selftest() {
  let n = 0;
  const assert = (c, m) => { if (!c) throw new Error("mesh-service selftest: " + m); n++; };

  const mesh = await import("./mesh.js");
  const fake = mesh.makeFakeMesh();
  const aClient = fake.client("aaaa"); // service host
  const bClient = fake.client("bbbb"); // querying peer

  // Start the REAL service on node A. The fake routes B's meshRequest onto A's stream with
  // a reply_token, and A's meshReply resolves it — exactly the production request/reply path.
  const svc = await startGovService(aClient, { readvertiseMs: 0 });
  assert(svc.serviceNames.includes(GOV_SERVICE) && svc.serviceNames.includes(GOV_VALIDATOR_SERVICE), "advertises both services");
  assert(svc.topics.includes(GOV_TOPIC), "subscribes GOV_TOPIC");

  // Helper: B issues a real /mesh/request to A's service and parses the reply.
  async function callService(reqObj, service = GOV_SERVICE) {
    const r = await bClient.meshRequest("aaaa", service, encodeJsonHex(reqObj), 2000);
    return decodeJsonHex(r && r.payload_hex);
  }

  // Announce a proposal + argument from B; A's service should index them.
  const propCid = await bClient.meshPutBlob(new TextEncoder().encode(JSON.stringify({ kind: "proposal", id: "p" })));
  const argCid = await bClient.meshPutBlob(new TextEncoder().encode(JSON.stringify({ kind: "argument", id: "g" })));
  await bClient.meshSubscribe(GOV_TOPIC);
  await mesh.announce(bClient, { type: EV.PROPOSAL, id: "p".repeat(64), cid: propCid, height: 5 });
  await mesh.announce(bClient, { type: EV.ARGUMENT, id: "g".repeat(64), cid: argCid, height: 6 });
  await fake.flush();
  assert(svc.index().length === 2, "service indexed 2 announced artifacts");

  // op:index over the service -> returns the index.
  const idxReply = await callService({ op: OP.INDEX });
  assert(idxReply && Array.isArray(idxReply.index) && idxReply.index.length === 2, "op:index returns the index");

  // op:get over the service -> returns the artifact JSON from the blob (A resolves it locally).
  const getReply = await callService({ op: OP.GET, cid: propCid });
  assert(getReply && getReply.artifact && getReply.artifact.kind === "proposal", "op:get returns the artifact");

  // op:validate over the service -> runs validator.js (deterministic; no LLM needed).
  const goodArg = {
    kind: "argument",
    proposal_id: "p".repeat(64),
    arg_kind: "proof",
    body: "Multiple jurisdictions classify this content as illegal to host on shared infra.",
    sources: [{ url: "https://example.org/statute", title: "Statute", trust: 80 }],
    author: "a".repeat(64),
    ts: 1,
  };
  const valReply = await callService({ op: OP.VALIDATE, argument: goodArg }, GOV_VALIDATOR_SERVICE);
  assert(valReply && valReply.validation && typeof valReply.validation.ok === "boolean", "op:validate returns a validation");

  // requestValidation helper (discovers the validator service + asks).
  const v2 = await requestValidation(bClient, goodArg, { timeout_ms: 2000 });
  assert(v2 && typeof v2.ok === "boolean", "requestValidation returns a validation from a peer");

  // unknown op -> structured error (never hangs).
  const errReply = await callService({ op: "nope" });
  assert(errReply && typeof errReply.error === "string", "unknown op returns an error reply");

  // getArtifact helper directly.
  const art = await getArtifact(bClient, argCid);
  assert(art && art.kind === "argument", "getArtifact parses a blob");

  svc.stop();
  return n;
}

if (
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1] &&
  import.meta.url === new URL(`file://${process.argv[1]}`).href
) {
  __selftest()
    .then((n) => console.log(`mesh-service.js selftest: OK (${n} assertions)`))
    .catch((err) => { console.error(err); process.exit(1); });
}
