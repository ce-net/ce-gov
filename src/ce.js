// @ce-net/gov — tiny zero-dep CE HTTP client.
//
// A thin `fetch` wrapper over the CE node HTTP API (docs/api.md, base http://localhost:8844).
// No dependencies; works in Node>=18 (native fetch) and the browser.
//
// Exposes exactly what the governance app needs:
//   - history(nodeId)        GET  /history/:node_id      (the reputation substrate)
//   - signalsSend(sig)       POST /signals/send          (broadcast a CEP-1 signal)
//   - signals()              GET  /signals               (last 100 validated signals)
//   - signalsStream(onMsg)   GET  /signals/stream        (SSE push; Node + browser)
//   - putBlob(bytes)         content-addressed store      (see "Blob storage" below)
//   - getBlob(cid)           content-addressed fetch
//   - beacon()               GET  /beacon                (verifiable randomness seed)
//   - status()               GET  /status                (node id, height, balance)
//
// AUTH: read-only GETs are open. Mutating POSTs need `Authorization: Bearer <api.token>`.
// Pass the token in the constructor opts (`token`) or via the `CE_API_TOKEN` env var.
//
// AMOUNTS: never parsed as numbers here — they stay decimal strings (use types.js `Amount`).
//
// ---------------------------------------------------------------------------
// Blob storage note
// ---------------------------------------------------------------------------
// api.md documents CEP-1 signals + the chain, but the former /sync file routes were moved to the
// `rdev` app and removed as node endpoints. primitives.md lists "content-addressed data: blobs +
// chunk fetch" as a CE primitive. To stay dependency-free and forward-compatible, the blob layer
// is PLUGGABLE: `putBlob`/`getBlob` go through `opts.blobStore`. Two implementations ship:
//   * `memoryBlobStore()`  — in-process Map (default; tests, single-process apps).
//   * `signalBlobStore(ce)` — persists small artifacts as the payload of a CEP-1 signal keyed by
//                             its content hash, retrievable via GET /signals. Suitable for the
//                             small JSON governance artifacts this app produces.
// When the node exposes a real blob route, add `httpBlobStore(base)` here without touching callers.

const DEFAULT_BASE = "http://localhost:8844";

/**
 * @typedef {Object} BlobStore
 * @property {(bytes: Uint8Array) => Promise<string>} put  returns the content id (cid)
 * @property {(cid: string) => Promise<Uint8Array|null>} get
 */

export class CeClient {
  /**
   * @param {Object} [opts]
   * @param {string} [opts.base]   API base URL (default env CE_API or http://localhost:8844)
   * @param {string} [opts.token]  Bearer token for mutating calls (default env CE_API_TOKEN)
   * @param {BlobStore} [opts.blobStore]  blob backend (default in-memory)
   * @param {typeof fetch} [opts.fetch]   fetch impl (default global fetch)
   */
  constructor(opts = {}) {
    const env = (typeof process !== "undefined" && process.env) || {};
    this.base = (opts.base || env.CE_API || DEFAULT_BASE).replace(/\/+$/, "");
    this.token = opts.token || env.CE_API_TOKEN || null;
    this.fetch = opts.fetch || globalThis.fetch;
    if (!this.fetch) throw new Error("no fetch available; pass opts.fetch");
    this.blobStore = opts.blobStore || memoryBlobStore();
  }

  /** @returns {HeadersInit} */
  _headers(mutating) {
    const h = { "Content-Type": "application/json" };
    if (mutating && this.token) h["Authorization"] = `Bearer ${this.token}`;
    return h;
  }

  async _get(path) {
    const res = await this.fetch(`${this.base}${path}`, { method: "GET", headers: this._headers(false) });
    if (!res.ok) throw new CeError(`GET ${path}`, res.status, await safeText(res));
    return res.json();
  }

  async _post(path, body) {
    const res = await this.fetch(`${this.base}${path}`, {
      method: "POST",
      headers: this._headers(true),
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new CeError(`POST ${path}`, res.status, await safeText(res));
    return res.status === 202 || res.status === 201 ? res.json().catch(() => ({})) : res.json().catch(() => ({}));
  }

  // ---- node info -----------------------------------------------------------

  /** GET /status -> { node_id, height, balance, weight, bond, ... } (amounts are strings). */
  async status() { return this._get("/status"); }

  /** GET /beacon -> { height, hash }. Verifiable randomness seed. */
  async beacon() { return this._get("/beacon"); }

  // ---- reputation substrate ------------------------------------------------

  /**
   * GET /history/:node_id -> NodeStats (jobs_hosted, earned, spent, slashes, expiries,
   * heartbeats, recent_earned/recent_spent, window_*). Amounts are base-unit strings.
   * @param {string} nodeId 64-hex
   */
  async history(nodeId) {
    if (!/^[0-9a-f]{64}$/.test(nodeId)) throw new TypeError("history: nodeId must be 64-hex");
    return this._get(`/history/${nodeId}`);
  }

  // ---- CEP-1 signals -------------------------------------------------------

  /**
   * POST /signals/send. Build, sign, broadcast a CEP-1 signal.
   * @param {Object} sig
   * @param {string} [sig.payload_hex]   hex payload (empty allowed for capability-only)
   * @param {string} [sig.to]            "broadcast" or 64-hex destination (default "broadcast")
   * @param {Array<{name:string,version:number}>} [sig.capabilities]
   * @param {string} [sig.burn_tx_id_hex] required by the node when payload_hex is non-empty
   * @returns {Promise<{id:string, nonce:number}>}
   */
  async signalsSend(sig) {
    const body = {
      payload_hex: sig.payload_hex || "",
      to: sig.to || "broadcast",
      capabilities: sig.capabilities || [],
    };
    if (sig.burn_tx_id_hex) body.burn_tx_id_hex = sig.burn_tx_id_hex;
    return this._post("/signals/send", body);
  }

  /** GET /signals -> last 100 validated CEP-1 signals (newest at end). */
  async signals() { return this._get("/signals"); }

  /**
   * GET /signals/stream (SSE). Calls `onMsg(parsedSignal)` for each event.
   * Returns an `{ close() }` handle. Works in browser (EventSource) and Node (streamed fetch).
   * @param {(signal: object) => void} onMsg
   * @param {(err: Error) => void} [onErr]
   */
  signalsStream(onMsg, onErr) {
    const url = `${this.base}/signals/stream`;
    if (typeof EventSource !== "undefined") {
      const es = new EventSource(url);
      es.onmessage = (e) => { try { onMsg(JSON.parse(e.data)); } catch (err) { onErr && onErr(err); } };
      es.onerror = (e) => { onErr && onErr(new Error("SSE error")); };
      return { close: () => es.close() };
    }
    // Node: stream the fetch body and parse `data:` lines.
    const controller = new AbortController();
    (async () => {
      try {
        const res = await this.fetch(url, { signal: controller.signal, headers: { Accept: "text/event-stream" } });
        if (!res.ok || !res.body) throw new CeError("GET /signals/stream", res.status, "");
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let i;
          while ((i = buf.indexOf("\n\n")) >= 0) {
            const frame = buf.slice(0, i);
            buf = buf.slice(i + 2);
            for (const line of frame.split("\n")) {
              if (line.startsWith("data:")) {
                try { onMsg(JSON.parse(line.slice(5).trim())); } catch (err) { onErr && onErr(err); }
              }
            }
          }
        }
      } catch (err) {
        if (err.name !== "AbortError") onErr && onErr(err);
      }
    })();
    return { close: () => controller.abort() };
  }

  // ---- content-addressed blobs (pluggable) --------------------------------

  /** Store bytes; returns the content id. @param {Uint8Array} bytes */
  async putBlob(bytes) { return this.blobStore.put(bytes); }

  /** Fetch bytes by content id, or null if absent. @param {string} cid */
  async getBlob(cid) { return this.blobStore.get(cid); }

  // ---- mesh: content-addressed blobs over the node /blobs route -----------
  //
  // These hit the node's REAL blob route directly (raw byte bodies, NOT JSON),
  // independent of the pluggable `blobStore` above. `httpBlobStore(ce)` wraps
  // them so the rest of the app can stay store-agnostic.

  /**
   * POST /blobs with a raw byte body. Returns the content id (64-hex sha256).
   * @param {Uint8Array} bytes
   * @returns {Promise<string>} cid
   */
  async meshPutBlob(bytes) {
    const body = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const headers = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const res = await this.fetch(`${this.base}/blobs`, { method: "POST", headers, body });
    if (!res.ok) throw new CeError("POST /blobs", res.status, await safeText(res));
    const j = await res.json();
    return j && j.hash;
  }

  /**
   * GET /blobs/:cid. Returns the raw bytes, or null on 404. The node DHT-resolves
   * on a local miss and verifies the bytes against the hash before returning them.
   * @param {string} cid 64-hex
   * @returns {Promise<Uint8Array|null>}
   */
  async meshGetBlob(cid) {
    const res = await this.fetch(`${this.base}/blobs/${cid}`, { method: "GET" });
    if (res.status === 404) return null;
    if (!res.ok) throw new CeError(`GET /blobs/${cid}`, res.status, await safeText(res));
    const buf = await res.arrayBuffer();
    return new Uint8Array(buf);
  }

  // ---- mesh: pub/sub (the live event bus) --------------------------------

  /**
   * POST /mesh/publish. Signs + auto-subscribes + gossips the message on `topic`.
   * @param {string} topic
   * @param {string} payload_hex
   * @returns {Promise<{status:string}>}
   */
  async meshPublish(topic, payload_hex) {
    return this._post("/mesh/publish", { topic, payload_hex });
  }

  /**
   * POST /mesh/subscribe. Idempotent; the subscription lasts the node lifetime.
   * @param {string} topic
   * @returns {Promise<{status:string}>}
   */
  async meshSubscribe(topic) {
    return this._post("/mesh/subscribe", { topic });
  }

  // ---- mesh: directed send / request / reply -----------------------------

  /**
   * POST /mesh/send. Fire-and-forget directed message to a peer.
   * @param {string} to 64-hex node id
   * @param {string} topic
   * @param {string} payload_hex
   * @returns {Promise<{status:string}>}
   */
  async meshSend(to, topic, payload_hex) {
    return this._post("/mesh/send", { to, topic, payload_hex });
  }

  /**
   * POST /mesh/request. Sends a request and BLOCKS until the peer replies (or timeout).
   * @param {string} to 64-hex node id
   * @param {string} topic
   * @param {string} payload_hex
   * @param {number} [timeout_ms=30000]
   * @returns {Promise<{payload_hex:string}>}
   */
  async meshRequest(to, topic, payload_hex, timeout_ms) {
    const body = { to, topic, payload_hex };
    if (timeout_ms !== undefined) body.timeout_ms = timeout_ms | 0;
    return this._post("/mesh/request", body);
  }

  /**
   * POST /mesh/reply. Answer an inbound /mesh/request by its reply_token.
   * @param {number} token  the inbound AppMessage.reply_token
   * @param {string} payload_hex
   * @returns {Promise<{status:string}>}
   */
  async meshReply(token, payload_hex) {
    return this._post("/mesh/reply", { token, payload_hex });
  }

  /** GET /mesh/messages -> snapshot ring of recent AppMessages. */
  async meshMessages() { return this._get("/mesh/messages"); }

  /**
   * GET /mesh/messages/stream (SSE). Calls `onMsg(appMessage)` for every inbound
   * message — directed sends, requests (with `reply_token`), and pubsub events all
   * arrive here. Reuses the same Node/browser SSE parsing as `signalsStream`.
   * @param {(m: {from:string,topic:string,payload_hex:string,received_at:number,reply_token?:number}) => void} onMsg
   * @param {(err: Error) => void} [onErr]
   * @returns {{ close(): void }}
   */
  meshStream(onMsg, onErr) {
    const url = `${this.base}/mesh/messages/stream`;
    if (typeof EventSource !== "undefined") {
      const es = new EventSource(url);
      es.onmessage = (e) => { try { onMsg(JSON.parse(e.data)); } catch (err) { onErr && onErr(err); } };
      es.onerror = () => { onErr && onErr(new Error("SSE error")); };
      return { close: () => es.close() };
    }
    const controller = new AbortController();
    (async () => {
      try {
        const res = await this.fetch(url, { signal: controller.signal, headers: { Accept: "text/event-stream" } });
        if (!res.ok || !res.body) throw new CeError("GET /mesh/messages/stream", res.status, "");
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let i;
          while ((i = buf.indexOf("\n\n")) >= 0) {
            const frame = buf.slice(0, i);
            buf = buf.slice(i + 2);
            for (const line of frame.split("\n")) {
              if (line.startsWith("data:")) {
                try { onMsg(JSON.parse(line.slice(5).trim())); } catch (err) { onErr && onErr(err); }
              }
            }
          }
        }
      } catch (err) {
        if (err.name !== "AbortError") onErr && onErr(err);
      }
    })();
    return { close: () => controller.abort() };
  }

  // ---- mesh: service discovery (DHT) -------------------------------------

  /**
   * POST /discovery/advertise. Become a provider of `service` in the DHT. Records
   * expire, so re-call periodically (mesh.js / mesh-service.js run a re-advertise loop).
   * @param {string} service
   * @returns {Promise<{status:string}>}
   */
  async meshAdvertise(service) {
    return this._post("/discovery/advertise", { service });
  }

  /**
   * GET /discovery/find/:service -> { service, providers:[64hex] }.
   * @param {string} service
   * @returns {Promise<{service:string, providers:string[]}>}
   */
  async meshFind(service) {
    return this._get(`/discovery/find/${encodeURIComponent(service)}`);
  }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class CeError extends Error {
  constructor(op, status, body) {
    super(`${op} -> ${status}${body ? `: ${body}` : ""}`);
    this.name = "CeError";
    this.status = status;
    this.body = body;
  }
}

async function safeText(res) { try { return await res.text(); } catch { return ""; } }

// ---------------------------------------------------------------------------
// Blob store implementations
// ---------------------------------------------------------------------------

/** In-process content-addressed store (cid = sha256 hex). @returns {BlobStore} */
export function memoryBlobStore() {
  const map = new Map();
  return {
    async put(bytes) {
      const cid = await sha256Hex(bytes);
      map.set(cid, bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes));
      return cid;
    },
    async get(cid) {
      const v = map.get(cid);
      return v ? v.slice() : null;
    },
  };
}

/**
 * Persist small artifacts as CEP-1 signal payloads, keyed by content hash.
 * put() broadcasts a signal whose payload_hex is the blob; get() scans GET /signals
 * for a matching content hash. Best-effort and bounded by the node's 100-signal window —
 * intended for the small JSON governance artifacts this app produces, broadcast at create time.
 * @param {CeClient} ce
 * @returns {BlobStore}
 */
export function signalBlobStore(ce) {
  return {
    async put(bytes) {
      const cid = await sha256Hex(bytes);
      await ce.signalsSend({ payload_hex: toHex(bytes), to: "broadcast" });
      return cid;
    },
    async get(cid) {
      const list = await ce.signals();
      for (const s of list) {
        if (!s.payload_hex) continue;
        const bytes = fromHex(s.payload_hex);
        if ((await sha256Hex(bytes)) === cid) return bytes;
      }
      return null;
    },
  };
}

/**
 * Real content-addressed blob store over the node's `/blobs` route (the production
 * backend). `put` POSTs raw bytes and returns the node-computed sha256 cid; `get`
 * GETs by cid (the node DHT-resolves + verifies on a local miss). This is the
 * mesh-native replacement for `memoryBlobStore`/`signalBlobStore` — pass it as
 * `blobStore` to go live, e.g. `new CeClient({ base, token, blobStore: httpBlobStore(...) })`.
 * The argument may be the partially-built CeClient (mesh methods are bound) — to avoid
 * a constructor ordering hazard, accept either a `{ meshPutBlob, meshGetBlob }` carrier
 * or a `{ base, token, fetch }` config and dial `/blobs` directly.
 * @param {CeClient | {base?:string, token?:string, fetch?:typeof fetch}} ceOrCfg
 * @returns {BlobStore}
 */
export function httpBlobStore(ceOrCfg) {
  const hasMethods =
    ceOrCfg && typeof ceOrCfg.meshPutBlob === "function" && typeof ceOrCfg.meshGetBlob === "function";
  if (hasMethods) {
    return {
      async put(bytes) { return ceOrCfg.meshPutBlob(bytes); },
      async get(cid) { return ceOrCfg.meshGetBlob(cid); },
    };
  }
  const env = (typeof process !== "undefined" && process.env) || {};
  const base = (ceOrCfg.base || env.CE_API || DEFAULT_BASE).replace(/\/+$/, "");
  const token = ceOrCfg.token || env.CE_API_TOKEN || null;
  const f = ceOrCfg.fetch || globalThis.fetch;
  if (!f) throw new Error("httpBlobStore: no fetch available; pass fetch");
  return {
    async put(bytes) {
      const body = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const headers = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;
      const res = await f(`${base}/blobs`, { method: "POST", headers, body });
      if (!res.ok) throw new CeError("POST /blobs", res.status, await safeText(res));
      const j = await res.json();
      return j && j.hash;
    },
    async get(cid) {
      const res = await f(`${base}/blobs/${cid}`, { method: "GET" });
      if (res.status === 404) return null;
      if (!res.ok) throw new CeError(`GET /blobs/${cid}`, res.status, await safeText(res));
      return new Uint8Array(await res.arrayBuffer());
    },
  };
}

// Local hex/hash helpers (kept self-contained so ce.js has no import cycle with types.js).
function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
async function sha256Hex(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const d = await crypto.subtle.digest("SHA-256", buf);
  return toHex(new Uint8Array(d));
}
