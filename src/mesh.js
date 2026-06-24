// @ce-net/gov — the governance MESH transport layer.
//
// This module is the thin, dependency-injected bridge between the governance app and
// the LOCAL node's verified mesh primitives (see PLAN/mesh-apps.md §1 and src/ce.js):
//
//   * STATE   — content-addressed blobs (`ce.meshPutBlob` / `ce.meshGetBlob`, i.e.
//               POST/GET /blobs). Artifacts are immutable, sha256-named, DHT-replicated.
//   * EVENTS  — pub/sub on the governance topic `GOV_TOPIC` (`ce.meshPublish` /
//               `ce.meshSubscribe`, inbound on `ce.meshStream`). REPLACES the old
//               CEP-1-signals-as-an-event-bus discovery path.
//   * QUERIES — request/reply to a DHT-advertised service `GOV_SERVICE`
//               (`ce.meshAdvertise` / `ce.meshFind` + `ce.meshRequest` / `ce.meshReply`),
//               so a fresh node can catch up its index from a peer.
//
// The wire shape that rides pubsub + request/reply is the small JSON *index event*
//   { type, id, cid, height }
// where `type` ∈ {proposal, argument, vote, verdict, policy}, `id` is the artifact's
// content id, `cid` is the blob cid to GET, and `height` is provenance. The blob is the
// source of truth; the event is the cache-invalidation / live-feed signal.
//
// DESIGN RULES (same as the rest of the app):
//   * No IO except through the injected `CeClient`. Pure helpers stay offline-testable.
//   * No host mutation, no central HTTP backend. Only the local node is touched.
//   * Hex/JSON helpers are self-contained (no import cycle with types.js).

/**
 * @typedef {import("./ce.js").CeClient} CeClient
 * @typedef {{ type:string, id:string, cid:string, height:number }} IndexEvent
 */

// ---------------------------------------------------------------------------
// Names — the DHT service + the pubsub topic the whole network agrees on.
// ---------------------------------------------------------------------------

/** DHT service name peers `find` to discover a governance query/validator endpoint. */
export const GOV_SERVICE = "ce-gov.v1";

/** Pubsub topic carrying governance index events (proposals/args/votes/verdicts/policies). */
export const GOV_TOPIC = "ce-gov.events.v1";

/**
 * The validator query service name (task §2). A node that runs the governance backend
 * advertises BOTH `GOV_SERVICE` (generic index/get) and this, so peers can route a
 * "validate this argument" request to a node that holds validator.js + reputation.js.
 */
export const GOV_VALIDATOR_SERVICE = "gov/validator";

/** Topic carrying proposal index events (subset of GOV_TOPIC consumers may scope to). */
export const TOPIC_PROPOSALS = "gov/proposals";

/** Topic carrying vote index events. */
export const TOPIC_VOTES = "gov/votes";

/** Event `type` discriminants carried in an IndexEvent. */
export const EV = Object.freeze({
  PROPOSAL: "proposal",
  ARGUMENT: "argument",
  VOTE: "vote",
  VERDICT: "verdict",
  POLICY: "policy",
});

/** Request `op` discriminants the GOV_SERVICE answers. */
export const OP = Object.freeze({
  INDEX: "index", // -> { index: IndexEvent[] }
  GET: "get",     // { cid } -> the artifact JSON (or null)
  VALIDATE: "validate", // { argument } -> ArgumentValidation verdict
});

// ---------------------------------------------------------------------------
// Pure helpers (offline-testable)
// ---------------------------------------------------------------------------

const _enc = new TextEncoder();
const _dec = new TextDecoder();

/** Hex-encode bytes. @param {Uint8Array} bytes @returns {string} */
export function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Hex-decode (tolerant: returns null on malformed input). @param {string} hex */
export function fromHex(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Encode any JSON-serializable object to a hex payload. @param {object} obj */
export function encodeJsonHex(obj) {
  return toHex(_enc.encode(JSON.stringify(obj)));
}

/** Decode a hex payload back to an object, or null on any error. @param {string} hex */
export function decodeJsonHex(hex) {
  const bytes = fromHex(hex);
  if (!bytes) return null;
  try {
    return JSON.parse(_dec.decode(bytes));
  } catch {
    return null;
  }
}

/**
 * Build + validate an IndexEvent from an artifact descriptor. Throws on a missing field
 * so an announce never silently publishes a malformed event.
 * @param {{type:string,id:string,cid:string,height?:number}} ev
 * @returns {IndexEvent}
 */
export function encodeEvent(ev) {
  if (!ev || typeof ev.type !== "string" || !ev.type) throw new TypeError("encodeEvent: type required");
  if (typeof ev.id !== "string" || !ev.id) throw new TypeError("encodeEvent: id required");
  if (typeof ev.cid !== "string" || !ev.cid) throw new TypeError("encodeEvent: cid required");
  return { type: ev.type, id: ev.id, cid: ev.cid, height: ev.height | 0 };
}

/**
 * Parse an inbound pubsub AppMessage's payload as an IndexEvent (or null). Defensive:
 * tolerates arbitrary traffic on the topic and only returns well-formed events.
 * @param {{payload_hex:string}} msg
 * @returns {IndexEvent|null}
 */
export function decodeEvent(msg) {
  if (!msg || typeof msg.payload_hex !== "string") return null;
  const obj = decodeJsonHex(msg.payload_hex);
  if (!obj || typeof obj.type !== "string" || typeof obj.id !== "string" || typeof obj.cid !== "string") {
    return null;
  }
  return { type: obj.type, id: obj.id, cid: obj.cid, height: obj.height | 0 };
}

// ---------------------------------------------------------------------------
// EVENTS — announce an artifact on the governance topic
// ---------------------------------------------------------------------------

/**
 * Publish an index event for a freshly-stored artifact on `GOV_TOPIC`. Best-effort:
 * the blob is already the source of truth, so a failed publish is swallowed (the artifact
 * is still discoverable via a service `index` query). REPLACES `proposals.js`'
 * `announceIndex` over CEP-1 signals.
 * @param {CeClient} ce
 * @param {{type:string,id:string,cid:string,height?:number}} ev
 * @returns {Promise<boolean>} true if the publish was accepted
 */
export async function announce(ce, ev) {
  const event = encodeEvent(ev);
  try {
    await ce.meshPublish(GOV_TOPIC, encodeJsonHex(event));
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// QUERIES — catch up a fresh node from a discovered service peer
// ---------------------------------------------------------------------------

/**
 * Discover a governance service peer via the DHT and request its current index, for a
 * fresh node to back-fill. REPLACES scanning `GET /signals`. Tries each provider until
 * one answers; returns `[]` (never throws) when no peer is reachable.
 * @param {CeClient} ce
 * @param {Object} [opts]
 * @param {string} [opts.service=GOV_SERVICE]
 * @param {number} [opts.timeout_ms=15000]
 * @param {number} [opts.maxPeers=3]   try at most this many providers
 * @returns {Promise<IndexEvent[]>}
 */
export async function fetchIndex(ce, opts = {}) {
  const service = opts.service || GOV_SERVICE;
  const timeout = opts.timeout_ms ?? 15000;
  const maxPeers = opts.maxPeers ?? 3;

  let providers = [];
  try {
    const found = await ce.meshFind(service);
    providers = (found && found.providers) || [];
  } catch {
    return [];
  }

  let selfId = null;
  try {
    const st = await ce.status();
    selfId = st && (st.node_id || st.id);
  } catch {
    /* status optional */
  }
  // Prefer peers other than ourselves (querying our own service is pointless).
  const ordered = providers.filter((p) => p !== selfId).concat(providers.filter((p) => p === selfId));

  for (const peer of ordered.slice(0, maxPeers)) {
    try {
      const r = await ce.meshRequest(peer, service, encodeJsonHex({ op: OP.INDEX }), timeout);
      const body = decodeJsonHex(r && r.payload_hex);
      const idx = body && Array.isArray(body.index) ? body.index : null;
      if (idx) {
        // Normalize defensively.
        return idx
          .map((e) => (e && e.type && e.id && e.cid ? { type: e.type, id: e.id, cid: e.cid, height: e.height | 0 } : null))
          .filter(Boolean);
      }
    } catch {
      // try the next provider
    }
  }
  return [];
}

/**
 * Request a single artifact JSON by cid from a discovered service peer (when the local
 * blob fetch missed and the caller wants an explicit pull). Returns the parsed artifact
 * or null. Usually unnecessary — `ce.meshGetBlob(cid)` already DHT-resolves — but exposed
 * for completeness / a service that gates blob access.
 * @param {CeClient} ce
 * @param {string} cid
 * @param {Object} [opts]
 * @returns {Promise<object|null>}
 */
export async function fetchArtifact(ce, cid, opts = {}) {
  const service = opts.service || GOV_SERVICE;
  const timeout = opts.timeout_ms ?? 15000;
  let providers = [];
  try {
    const found = await ce.meshFind(service);
    providers = (found && found.providers) || [];
  } catch {
    return null;
  }
  for (const peer of providers.slice(0, opts.maxPeers ?? 3)) {
    try {
      const r = await ce.meshRequest(peer, service, encodeJsonHex({ op: OP.GET, cid }), timeout);
      const body = decodeJsonHex(r && r.payload_hex);
      if (body && body.artifact) return body.artifact;
      if (body && body.kind) return body; // service may reply the artifact directly
    } catch {
      /* next peer */
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// SSE filter helper — turn the raw mesh stream into governance index events
// ---------------------------------------------------------------------------

/**
 * Subscribe to `GOV_TOPIC` and stream decoded IndexEvents. Wraps `ce.meshStream`,
 * filtering to pubsub messages (no `reply_token`) on the governance topic. Calls
 * `onEvent(indexEvent, rawMsg)`. Returns `{ close() }`. The frontend live feed uses
 * the same filter against the open SSE endpoint.
 * @param {CeClient} ce
 * @param {(ev:IndexEvent, raw:object)=>void} onEvent
 * @param {Object} [opts]
 * @param {(err:Error)=>void} [opts.onErr]
 * @param {boolean} [opts.subscribe=true]   also POST /mesh/subscribe(GOV_TOPIC) first
 * @returns {{ close():void }}
 */
export function watchEvents(ce, onEvent, opts = {}) {
  if (opts.subscribe !== false && ce && typeof ce.meshSubscribe === "function") {
    Promise.resolve(ce.meshSubscribe(GOV_TOPIC)).catch((e) => opts.onErr && opts.onErr(e));
  }
  if (!ce || typeof ce.meshStream !== "function") return { close() {} };
  return ce.meshStream((m) => {
    if (!m || m.reply_token != null) return; // pubsub events only
    if (m.topic !== GOV_TOPIC) return;
    const ev = decodeEvent(m);
    if (ev) onEvent(ev, m);
  }, opts.onErr);
}

// ---------------------------------------------------------------------------
// Self-test (no network) — run with: node src/mesh.js
// ---------------------------------------------------------------------------

/**
 * Offline self-test of the pure helpers + announce/fetchIndex/watchEvents against an
 * in-memory fake CeClient (a tiny pubsub + request/reply + DHT bus). No network.
 * @returns {Promise<number>} assertions passed
 */
export async function __selftest() {
  let n = 0;
  const assert = (c, m) => { if (!c) throw new Error("mesh selftest: " + m); n++; };

  // hex round-trips
  const ev = { type: EV.PROPOSAL, id: "a".repeat(64), cid: "b".repeat(64), height: 42 };
  const hex = encodeJsonHex(ev);
  assert(/^[0-9a-f]+$/.test(hex), "encodeJsonHex yields hex");
  const back = decodeJsonHex(hex);
  assert(back && back.id === ev.id && back.cid === ev.cid, "decodeJsonHex round-trips");
  assert(decodeJsonHex("zz") === null, "decodeJsonHex tolerant of bad hex");

  // encodeEvent / decodeEvent
  const enc1 = encodeEvent({ type: EV.VOTE, id: "1".repeat(64), cid: "2".repeat(64) });
  assert(enc1.height === 0, "encodeEvent defaults height 0");
  let threw = false;
  try { encodeEvent({ id: "x", cid: "y" }); } catch { threw = true; }
  assert(threw, "encodeEvent rejects missing type");
  const dec1 = decodeEvent({ payload_hex: encodeJsonHex(enc1) });
  assert(dec1 && dec1.type === EV.VOTE, "decodeEvent parses an IndexEvent");
  assert(decodeEvent({ payload_hex: encodeJsonHex({ junk: true }) }) === null, "decodeEvent rejects non-event");

  // A fake in-process mesh: pubsub + directed request/reply + DHT.
  const fake = makeFakeMesh();
  const a = fake.client("aaaa");
  const b = fake.client("bbbb");

  // announce publishes to GOV_TOPIC; a watcher on the OTHER node sees it (no self-echo).
  const seen = [];
  await b.meshSubscribe(GOV_TOPIC); // ensure subscription is in place before announce
  const sub = watchEvents(b, (e) => seen.push(e), { subscribe: false });
  await announce(a, { type: EV.PROPOSAL, id: "p".repeat(64), cid: "c".repeat(64), height: 7 });
  await fake.flush();
  assert(seen.length === 1 && seen[0].type === EV.PROPOSAL && seen[0].height === 7, "watchEvents sees announced event");
  sub.close();

  // Node A advertises GOV_SERVICE and answers an index request off its OWN stream (exactly
  // how a real service replies). B's fetchIndex discovers A and catches up.
  await a.meshAdvertise(GOV_SERVICE);
  const aReq = a.meshStream(async (m) => {
    if (m.reply_token == null) return;
    const body = decodeJsonHex(m.payload_hex);
    if (body && body.op === OP.INDEX) {
      await a.meshReply(m.reply_token, encodeJsonHex({ index: [{ type: EV.PROPOSAL, id: "p".repeat(64), cid: "c".repeat(64), height: 7 }] }));
    }
  });
  const idx = await fetchIndex(b, { timeout_ms: 1000 });
  assert(idx.length === 1 && idx[0].cid === "c".repeat(64), "fetchIndex catches up from a peer");
  aReq.close();

  return n;
}

// A minimal in-memory mesh used by the self-test (and importable by mesh-service.js's test).
// Models: meshPublish/meshSubscribe/meshStream (pubsub), meshSend, meshRequest/meshReply
// (directed request/reply), meshAdvertise/meshFind (DHT), meshPutBlob/meshGetBlob (blobs),
// and status() for self-id. Single-process, synchronous-ish via a microtask flush.
export function makeFakeMesh() {
  // A single-process model of the node mesh that mirrors the real routing semantics used
  // by mesh.js / mesh-service.js:
  //   * pubsub: a publish on a topic reaches every node that subscribed AND opened a stream
  //     (reply_token absent), matching the node's "publish auto-subscribes + inbound on SSE".
  //   * request/reply: meshRequest(to, service, ...) delivers an inbound message onto the
  //     TARGET node's stream with a synthetic reply_token; the target answers via meshReply,
  //     which resolves the original meshRequest promise. This is exactly how a real service
  //     (mesh-service.js) handles a request — off the same stream — so the test exercises
  //     the production code path, not a shortcut.
  //   * DHT: advertise/find by service name.
  //   * blobs: content-addressed by sha256.
  const nodes = new Map();      // nodeId -> { subs:Set<topic>, streams:Set<onMsg> }
  const blobs = new Map();      // cid -> Uint8Array
  const replyWaiters = new Map(); // reply_token -> { resolve, reject }
  const advertised = new Map(); // service -> Set<nodeId>
  let tokenSeq = 1;

  function node(id) {
    if (!nodes.has(id)) nodes.set(id, { subs: new Set(), streams: new Set() });
    return nodes.get(id);
  }

  async function sha256Hex(bytes) {
    const d = await crypto.subtle.digest("SHA-256", bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    let s = "";
    for (const x of new Uint8Array(d)) s += x.toString(16).padStart(2, "0");
    return s;
  }

  function deliver(targetId, msg) {
    const st = nodes.get(targetId);
    if (!st) return;
    for (const onMsg of st.streams) Promise.resolve(onMsg(msg)).catch(() => {});
  }

  function client(nodeId) {
    node(nodeId);
    return {
      async status() { return { node_id: nodeId, height: 100 }; },
      async meshPublish(topic, payload_hex) {
        for (const [id, st] of nodes) {
          if (id === nodeId) continue; // don't echo to self (node gossip excludes origin)
          if (st.subs.has(topic)) deliver(id, { from: nodeId, topic, payload_hex, received_at: 0 });
        }
        return { status: "published" };
      },
      async meshSubscribe(topic) { node(nodeId).subs.add(topic); return { status: "subscribed" }; },
      meshStream(onMsg) {
        node(nodeId).streams.add(onMsg);
        return { close() { node(nodeId).streams.delete(onMsg); } };
      },
      async meshAdvertise(service) {
        if (!advertised.has(service)) advertised.set(service, new Set());
        advertised.get(service).add(nodeId);
        return { status: "advertised" };
      },
      async meshFind(service) {
        return { service, providers: [...(advertised.get(service) || [])] };
      },
      async meshRequest(to, service, payload_hex, timeout_ms = 5000) {
        const token = tokenSeq++;
        return new Promise((resolve, reject) => {
          const timer = setTimeout(() => { replyWaiters.delete(token); reject(new Error("timeout")); }, timeout_ms);
          if (timer && typeof timer.unref === "function") timer.unref();
          replyWaiters.set(token, {
            resolve: (payload) => { clearTimeout(timer); resolve({ payload_hex: payload }); },
          });
          deliver(to, { from: nodeId, topic: service, payload_hex, received_at: 0, reply_token: token });
        });
      },
      async meshReply(token, payload_hex) {
        const w = replyWaiters.get(token);
        if (w) { replyWaiters.delete(token); w.resolve(payload_hex); }
        return { status: "replied" };
      },
      async meshSend() { return { status: "delivered" }; },
      async meshPutBlob(bytes) {
        const cid = await sha256Hex(bytes);
        blobs.set(cid, bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes));
        return cid;
      },
      async meshGetBlob(cid) {
        const v = blobs.get(cid);
        return v ? v.slice() : null;
      },
    };
  }

  return {
    client,
    // settle queued microtasks (delivery is via resolved promises)
    async flush() { for (let i = 0; i < 8; i++) await Promise.resolve(); },
  };
}

if (
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1] &&
  import.meta.url === new URL(`file://${process.argv[1]}`).href
) {
  __selftest()
    .then((n) => console.log(`mesh.js selftest: OK (${n} assertions)`))
    .catch((err) => { console.error(err); process.exit(1); });
}
