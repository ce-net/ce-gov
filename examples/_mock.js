// @ce-net/gov examples — shared in-memory mocks (NO NETWORK).
//
// These let every example run with `node examples/<x>.js` without a live CE node or an
// ANTHROPIC_API_KEY. They mirror the real surfaces the modules use:
//   * MockCe         — an in-memory CeClient (blob store + signal bus + status/beacon).
//   * makeSigner     — a deterministic test signer (NOT cryptographic; demo provenance only).
//   * makeVerifySig  — the matching verifier (pairs with makeSigner).
//   * stubScanLlm    — a scan classifier (scan.js Validator) with a scripted decision.
//   * stubEvidenceLlm— a validator.js LlmAdapter that returns a scripted judgement.
//
// Real deployments inject a real CeClient (src/ce.js), a node-key signer/verifier
// (ce-cap), and a real LLM adapter (makeValidatorLlm / makeScanValidator).

import { sha256Hex } from "../src/types.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

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

/**
 * In-memory CE client. Content-addressed blob store, an append-only signal bus, and
 * fixed status/beacon. `signalsStream` replays buffered signals then fires future ones.
 */
export class MockCe {
  constructor({ height = 100, beaconHash = "f".repeat(64) } = {}) {
    this._blobs = new Map();
    this._signals = [];
    this._listeners = new Set();
    this._height = height;
    this._beaconHash = beaconHash;
    this._nodeId = "c".repeat(64);
  }

  async status() {
    return { node_id: this._nodeId, height: this._height, balance: "0" };
  }
  async beacon() {
    return { height: this._height, hash: this._beaconHash };
  }
  async history() {
    // unknown node => zero stats (graceful-degrade path); overridden per-example as needed.
    return {};
  }

  async putBlob(bytes) {
    const cid = await sha256Hex(bytes);
    const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes);
    this._blobs.set(cid, copy);
    // Mirror `signalBlobStore` semantics: a stored artifact is ALSO broadcast as a CEP-1
    // signal so discovery layers that scan GET /signals (policy.collectPolicies,
    // scan.findCachedVerdict, monitor.collectReports) can find it. This is how a real
    // deployment wires durable+discoverable artifacts; the default in-memory blob store
    // alone is not discoverable, which is why production uses signalBlobStore(ce).
    this._signals.push({ payload_hex: toHex(copy), to: "broadcast", from: this._nodeId });
    return cid;
  }
  async getBlob(cid) {
    const v = this._blobs.get(cid);
    return v ? v.slice() : null;
  }

  async signalsSend(sig) {
    const rec = { payload_hex: sig.payload_hex || "", to: sig.to || "broadcast", from: this._nodeId };
    this._signals.push(rec);
    for (const fn of this._listeners) {
      try { fn(rec); } catch { /* ignore listener errors in the mock */ }
    }
    const id = (await sha256Hex(enc.encode(rec.payload_hex))).slice(0, 16);
    return { id, nonce: this._signals.length };
  }
  async signals() {
    return this._signals.slice();
  }
  signalsStream(onMsg) {
    for (const s of this._signals) onMsg(s);
    this._listeners.add(onMsg);
    return { close: () => this._listeners.delete(onMsg) };
  }

  /** Inject a raw signal (e.g. a synthetic job-metering sample for the monitor demo). */
  inject(rec) {
    this._signals.push(rec);
    for (const fn of this._listeners) {
      try { fn(rec); } catch { /* ignore */ }
    }
  }
}

/**
 * Deterministic, NON-cryptographic demo signer: returns a 128-hex tag derived from the
 * payload. Pairs with `makeVerifySig`. Real signing is a node-key/ce-cap operation.
 * @param {string} [tag]  author label folded into the signature so distinct authors differ
 */
export function makeSigner(tag = "demo") {
  return async (payload) => {
    const h = await sha256Hex(enc.encode(`${tag}:${payload}`));
    return (h + h).slice(0, 128);
  };
}

/** Verifier matching `makeSigner(tag)`. @param {string} [tag] */
export function makeVerifySig(tag = "demo") {
  const signer = makeSigner(tag);
  return async (payload, sig /*, author */) => {
    try {
      return (await signer(payload)) === sig;
    } catch {
      return false;
    }
  };
}

/**
 * A scan.js `Validator` (classifyArtifact/available) with a scripted decision. Use to
 * demo the LLM stage without a real API key.
 * @param {{decision?:'allow'|'deny', categories?:string[], confidence?:number, rationale?:string, model_id?:string}} [script]
 */
export function stubScanLlm(script = {}) {
  return {
    available: () => true,
    classifyArtifact: async () => ({
      decision: script.decision || "allow",
      categories: script.categories || [],
      confidence: script.confidence ?? 88,
      rationale: script.rationale || "stub classifier verdict",
      model_id: script.model_id || "stub-scan-model",
      prompt_template_hash: "e".repeat(64),
      deterministic: false,
    }),
  };
}

/**
 * A validator.js `LlmAdapter` (available/judge) with a scripted judgement, for the
 * argument-evidence path.
 * @param {{sound?:boolean, overall_confidence?:number, rationale?:string,
 *          sources?:Array<{index:number,stance:string,confidence:number}>, model_id?:string}} [script]
 */
export function stubEvidenceLlm(script = {}) {
  return {
    available: () => true,
    judge: async (req) => ({
      sound: script.sound ?? true,
      overall_confidence: script.overall_confidence ?? 85,
      rationale: script.rationale || "stub evidence judgement",
      fallacies: script.fallacies || [],
      sources:
        script.sources ||
        (req.sources || []).map((_, i) => ({ index: i, stance: "support", confidence: 90 })),
      model_id: script.model_id || "stub-evidence-model",
    }),
  };
}

export const hex = { toHex, fromHex };
export { dec, enc };
