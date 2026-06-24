// @ce-net/gov — public entry point.
//
// Re-exports the public API of every module and provides a single dependency-injected
// `Governance` facade that wires reputation + proposals + voting + validator + scan +
// monitor + policy together over one CE client and one LLM adapter.
//
// USAGE
// -----
//   import { Governance, CeClient } from "@ce-net/gov";          // (or "./src/index.js")
//   const gov = new Governance({
//     ce: new CeClient({ base: "http://localhost:8844" }),
//     signer: async (payload) => signWithNodeKey(payload),       // (payload)=>128-hex
//     verifySig: async (payload, sig, author) => verify(...),    // (payload,sig,author)=>bool
//     // llm omitted => deterministic-only graceful degrade (no ANTHROPIC_API_KEY needed)
//   });
//
//   const proposal = await gov.createProposal({ ... });
//   await gov.argue({ proposal_id: proposal.id, arg_kind: "proof", body, sources });
//   await gov.vote({ proposal_id: proposal.id, direction: "up" });
//   const verdict = await gov.finalize(proposal);                // after close_height
//   await gov.enact(verdict, proposal);                          // -> active Policy
//   const v = await gov.scanArtifact({ artifact_digest, source_url, cmd, ... });
//   gov.monitor({ onSuspect, onReport });
//
// DESIGN
// ------
//   * The facade NEVER constructs identity/signing; the caller injects `signer`/`verifySig`
//     (wired to ce-cap / the node identity / a browser wallet). With no signer, artifacts are
//     content-addressed but unsigned — useful for local computation and the offline examples.
//   * One LLM adapter is shared by the validator (argument evidence) and the scan (artifact
//     classification). It degrades gracefully: with no key/backend, deterministic checks still run.
//   * The validator module returns an `ArgumentValidation`; voting.js and monitor.js want a
//     `{ verifyEvidence(arg) }` adapter. The facade bridges the two via `makeEvidenceValidator`
//     so the same LLM/deterministic stack feeds tallies and abuse re-checks.

// ---------------------------------------------------------------------------
// Re-exports — the full public surface of each module
// ---------------------------------------------------------------------------

export * from "./types.js";
export * from "./ce.js";
export * from "./reputation.js";
export * from "./proposals.js";
export * from "./voting.js";
export * from "./validator.js";
export * from "./scan.js";
export * from "./monitor.js";
export * from "./policy.js";
export * from "./mesh.js";
export * from "./mesh-service.js";

// Module namespaces. `export *` drops any name defined in two modules (e.g. both
// scan.js and validator.js export `deterministicChecks`; scan.js and policy.js both
// export `DEFAULT_BANNED_CATEGORIES`; several export `__selftest`). Those ambiguous
// names resolve to `undefined` on the flat surface, so we ALSO expose every module's
// full surface under a stable `ns*` namespace alias — consumers reach a collided
// symbol via `gov.nsScan.deterministicChecks` / `gov.nsValidator.deterministicChecks`.
// (The aliases are `ns`-prefixed so they never collide with flat function exports such
// as `scan` / `validator` from `export *`.)
export {
  Types as nsTypes,
  Reputation as nsReputation,
  Proposals as nsProposals,
  Voting as nsVoting,
  Validator as nsValidator,
  Scan as nsScan,
  Monitor as nsMonitor,
  Policy as nsPolicy,
  Mesh as nsMesh,
  MeshService as nsMeshService,
};

// Named imports the facade wires together. (Selective, to avoid name ambiguity:
// scan.js and validator.js both export `deterministicChecks`, `__selftest`, etc.;
// the facade refers to them through their module namespaces below.)
import { CeClient, httpBlobStore } from "./ce.js";
import * as Types from "./types.js";
import * as Reputation from "./reputation.js";
import * as Proposals from "./proposals.js";
import * as Voting from "./voting.js";
import * as Validator from "./validator.js";
import * as Scan from "./scan.js";
import * as Monitor from "./monitor.js";
import * as Policy from "./policy.js";
import * as Mesh from "./mesh.js";
import * as MeshService from "./mesh-service.js";

// ---------------------------------------------------------------------------
// Evidence-validator bridge
// ---------------------------------------------------------------------------

/**
 * Adapt the argument-evidence validator (`validator.js validateArgument`, which returns
 * an `ArgumentValidation`) into the `{ available, verifyEvidence(arg) }` shape that
 * `voting.js tally()` and `monitor.js reportAbuse()` consume.
 *
 * `verifyEvidence(arg)` returns `{ supported, sourceTrust, confidence, verdict_id }`:
 *   * `supported`   — the argument passed (structurally valid AND score >= PASS_SCORE);
 *   * `sourceTrust` — the max trusted source trust (0..100), so the tally's MIN_SOURCE_TRUST
 *                     gate is meaningful;
 *   * `confidence`  — the evidence-quality score (0..100);
 *   * `verdict_id`  — the recomputed content id of the argument (provenance for AbuseReport).
 *
 * @param {Object} [opts]
 * @param {import("./validator.js").LlmAdapter} [opts.llm]  shared LLM adapter
 * @param {(url:string)=>Promise<boolean>} [opts.probe]     optional reachability probe
 * @param {(url:string)=>number} [opts.trustOf]             optional source-trust resolver
 * @param {(payload:string)=>Promise<boolean>} [opts.verifySig]  optional signature verifier
 * @returns {{ available:()=>boolean,
 *             verifyEvidence:(arg:object)=>Promise<{supported:boolean,sourceTrust:number,confidence:number,verdict_id?:string,validation?:object}> }}
 */
export function makeEvidenceValidator(opts = {}) {
  const llm = opts.llm || Validator.makeValidatorLlm();
  return {
    available: () => !!(llm && typeof llm.available === "function" && llm.available()),
    async verifyEvidence(arg) {
      const v = await Validator.validateArgument(arg, {
        llm,
        probe: opts.probe,
        trustOf: opts.trustOf,
        verifySig: opts.verifySig,
      });
      const sourceTrust = (v.sourceVerdicts || []).reduce(
        (max, sv) => (sv && sv.trusted && sv.schemeOk && !sv.duplicate ? Math.max(max, sv.trust | 0) : max),
        0,
      );
      return {
        supported: !!v.ok,
        sourceTrust,
        confidence: v.score | 0,
        verdict_id: v.argument_id,
        validation: v,
      };
    },
  };
}

// ---------------------------------------------------------------------------
// The Governance facade
// ---------------------------------------------------------------------------

/**
 * One object that wires the whole app over an injected CE client + LLM adapter.
 *
 * Every method is a thin, documented delegation to a module function with the shared
 * dependencies pre-bound (ce, signer, verifySig, llm, the evidence validator, and the
 * scan classifier). Modules remain independently importable; the facade is convenience,
 * not a hidden god-object — it constructs nothing the modules could not be handed directly.
 */
export class Governance {
  /**
   * @param {Object} [opts]
   * @param {import("./ce.js").CeClient} [opts.ce]   CE client (default: new CeClient()).
   * @param {(payload:string)=>Promise<string>} [opts.signer]
   *        sign a canonical payload -> 128-hex. Omit for unsigned/local computation.
   * @param {(payload:string, sig:string, author:string)=>(boolean|Promise<boolean>)} [opts.verifySig]
   *        verify an artifact signature (ce-cap / node identity / wallet).
   * @param {import("./validator.js").LlmAdapter} [opts.llm]
   *        shared LLM adapter; default `makeValidatorLlm()` (Claude if ANTHROPIC_API_KEY, else none).
   * @param {import("./scan.js").Validator} [opts.scanValidator]
   *        scan classifier; default `makeScanValidator()` over the same backend selection.
   * @param {(url:string)=>Promise<boolean>} [opts.probe]   optional URL reachability probe.
   * @param {(url:string)=>number} [opts.trustOf]           optional source-trust resolver.
   * @param {boolean} [opts.allowUnsigned]  accept unsigned votes/args in tallies (local/tests).
   * @param {string} [opts.author]          default author for self-authored artifacts.
   * @param {boolean} [opts.mesh]           opt into the production mesh backend: store
   *        artifacts via the node's real `/blobs` route (`httpBlobStore`). Default false so
   *        offline examples/tests keep the in-memory blob store. Ignored if `opts.ce` already
   *        carries a non-default `blobStore`.
   */
  constructor(opts = {}) {
    this.ce = opts.ce || new CeClient();
    this.signer = opts.signer || null;
    this.verifySig = opts.verifySig || null;
    this.allowUnsigned = !!opts.allowUnsigned;
    this.author = opts.author || null;
    this._service = null; // mesh-service handle once start() is called

    // Production mesh backend: wire the blob store to the node's real /blobs route. We only
    // do this when explicitly asked (opts.mesh) and the ce client supports the mesh blob
    // methods, so offline construction (no node) is never broken.
    if (opts.mesh && this.ce && typeof this.ce.meshPutBlob === "function") {
      this.ce.blobStore = httpBlobStore(this.ce);
    }

    // One LLM adapter, shared by argument validation and artifact scanning.
    this.llm = opts.llm || Validator.makeValidatorLlm(opts);

    // The evidence validator bridge (voting + monitor consume this).
    this.evidence = makeEvidenceValidator({
      llm: this.llm,
      probe: opts.probe,
      trustOf: opts.trustOf,
      verifySig: this.verifySig ? (p, s, a) => this.verifySig(p, s, a) : undefined,
    });

    // The artifact-scan classifier (scan.js Validator).
    this.scanValidator = opts.scanValidator || Scan.makeScanValidator(opts);
  }

  // ---- mesh service lifecycle --------------------------------------------

  /**
   * Start the node-side governance mesh service: advertise `ce-gov.v1` + `gov/validator` in
   * the DHT, subscribe to the governance topics, maintain the discovery index from announced
   * blob CIDs, and answer `index` / `get` / `validate` requests over request/reply. Reuses
   * this facade's shared LLM/validator stack for `validate`. Idempotent (returns the existing
   * handle if already started). Requires a node with `/mesh/*` (a mesh-capable ce client).
   * @param {Object} [opts]  passthrough to `startGovService` (readvertiseMs, onEvent, onErr).
   * @returns {Promise<{stop:()=>void, index:()=>object[], validate:(arg:object)=>Promise<object>, serviceNames:string[], topics:string[]}>}
   */
  async start(opts = {}) {
    if (this._service) return this._service;
    if (!this.ce || typeof this.ce.meshAdvertise !== "function") {
      throw new TypeError("Governance.start requires a mesh-capable CE client (node with /mesh/*)");
    }
    this._service = await MeshService.startGovService(this.ce, {
      llm: this.llm,
      verifySig: this.verifySig ? (p, s, a) => this.verifySig(p, s, a) : undefined,
      ...opts,
    });
    return this._service;
  }

  /** Stop the governance mesh service started by `start()`. No-op if not started. */
  stop() {
    if (this._service) {
      try { this._service.stop(); } catch { /* ignore */ }
      this._service = null;
    }
  }

  // ---- node / reputation -------------------------------------------------

  /** GET /status passthrough. @returns {Promise<object>} */
  status() { return this.ce.status(); }

  /** GET /beacon passthrough. @returns {Promise<{height:number,hash:string}>} */
  beacon() { return this.ce.beacon(); }

  /**
   * Compute a node's reputation profile (karma + per-tag expertise) from /history.
   * @param {string} nodeId 64-hex
   * @param {string[]} [tags]
   * @returns {Promise<import("./types.js").NodeProfileLite>}
   */
  profile(nodeId, tags = []) {
    return Reputation.profile(this.ce, nodeId, { tags });
  }

  // ---- (c) governance: proposals + arguments + votes ---------------------

  /**
   * Create a policy proposal (e.g. "Ban hosting of pornographic content").
   * @param {Partial<import("./types.js").PolicyProposal>} fields
   * @returns {Promise<import("./types.js").PolicyProposal>}
   */
  createProposal(fields) {
    return Proposals.createProposal(this.ce, this._withAuthor(fields), this.signer);
  }

  /**
   * Attach a proof / antiproof argument (with required cited sources) to a proposal.
   * @param {Partial<import("./types.js").Argument>} fields
   * @returns {Promise<import("./types.js").Argument>}
   */
  argue(fields) {
    return Proposals.addArgument(this.ce, this._withAuthor(fields), this.signer);
  }

  /** Load a proposal by id. @param {string} id */
  loadProposal(id) { return Proposals.loadProposal(this.ce, id); }

  /** Load all arguments for a proposal. @param {string} proposalId */
  loadArguments(proposalId) { return Proposals.loadArguments(this.ce, proposalId); }

  /** List proposals discovered on the mesh. @param {object} [filter] */
  listProposals(filter = {}) { return Proposals.listProposals(this.ce, filter); }

  /**
   * Validate one argument's evidence (deterministic + optional LLM). Returns the full
   * `ArgumentValidation` (ok/score/issues/sourceVerdicts/...).
   * @param {import("./types.js").Argument} argument
   * @returns {Promise<import("./validator.js").ArgumentValidation>}
   */
  validateArgument(argument) {
    return Validator.validateArgument(argument, {
      llm: this.llm,
      verifySig: this.verifySig ? (p, s, a) => this.verifySig(p, s, a) : undefined,
    });
  }

  /**
   * Cast a vote on a proposal (or a specific argument). Weight is derived from the
   * voter's /history reputation unless overridden in `opts.weight`.
   * @param {Partial<import("./types.js").Vote>} fields
   * @param {Object} [opts]  { expertise_tags?, weight? }
   * @returns {Promise<import("./types.js").Vote>}
   */
  vote(fields, opts = {}) {
    return Voting.castVote(this.ce, this._withAuthor(fields), this.signer, opts);
  }

  /**
   * Tally a proposal's votes + arguments (does not require the window to be closed).
   * The shared evidence validator gates argument contributions.
   * @param {import("./types.js").PolicyProposal} proposal
   * @param {import("./types.js").Vote[]} votes
   * @param {import("./types.js").Argument[]} args
   * @param {object} [opts]
   * @returns {Promise<object>}  { tally_for, tally_against, voter_count, passed, decision, quorum_met }
   */
  tally(proposal, votes, args, opts = {}) {
    return Voting.tally(this.ce, proposal, votes, args, this._tallyOpts(opts));
  }

  /**
   * Finalize a CLOSED proposal into a signed Verdict (tally + beacon stamp). Throws if
   * the proposal is still open (current height <= close_height).
   * @param {import("./types.js").PolicyProposal} proposal
   * @param {import("./types.js").Vote[]} [votes]
   * @param {import("./types.js").Argument[]} [args]
   * @param {object} [opts]
   * @returns {Promise<import("./types.js").Verdict>}
   */
  async finalize(proposal, votes, args, opts = {}) {
    const v = votes || [];
    const a = args || (await this.loadArguments(proposal.id));
    return Voting.finalizeVerdict(this.ce, proposal, v, a, this.signer, this._tallyOpts(opts));
  }

  // ---- (a)+(c) policy: enact verdict, read active set --------------------

  /**
   * Enact a PASSING verdict into a signed, persisted Policy (folds into the active set).
   * @param {import("./types.js").Verdict} verdict
   * @param {import("./types.js").PolicyProposal} proposal
   * @returns {Promise<import("./types.js").Policy>}
   */
  enact(verdict, proposal) {
    return Policy.enactFromVerdict(this.ce, verdict, proposal, this.signer);
  }

  /**
   * Resolve the current active policy set (the single source of truth for "what is banned").
   * @param {object} [opts]
   * @returns {Promise<import("./policy.js").ActivePolicySet>}
   */
  activePolicy(opts = {}) { return Policy.activePolicySet(this.ce, opts); }

  /**
   * Render the active set as the node Guardian's `GuardPolicy.banned_categories` shape.
   * Adoption is per-operator opt-in (no global oracle).
   * @param {import("./policy.js").ActivePolicySet} [policySet]
   * @returns {Promise<import("./policy.js").GuardPolicyExport>}
   */
  async guardPolicyExport(policySet) {
    const set = policySet || (await this.activePolicy());
    return Policy.guardPolicyExport(set);
  }

  /**
   * Subscribe to active-policy-set changes (fires once immediately, then on id change).
   * @param {(policySet:import("./policy.js").ActivePolicySet)=>void} cb
   * @param {object} [opts]
   * @returns {{ close():void }}
   */
  watchPolicy(cb, opts = {}) { return Policy.subscribe(this.ce, cb, opts); }

  // ---- (a) pre-run scan --------------------------------------------------

  /**
   * Run the pre-run policy scan for an artifact -> signed, cached ScanVerdict. Uses the
   * shared scan classifier and resolves the active policy set automatically (unless an
   * `opts.activePolicySet` loader is given).
   * @param {Partial<import("./types.js").ScanRequest>} fields
   * @param {object} [opts]
   * @returns {Promise<import("./types.js").ScanVerdict>}
   */
  scanArtifact(fields, opts = {}) {
    return Scan.scan(this.ce, this.scanValidator, this._withAuthor(fields), this.signer, opts);
  }

  /** Whether a ScanVerdict permits launch (ALLOW only; fail-closed). */
  isAllowed(verdict) { return Scan.isAllowed(verdict); }

  // ---- (b) runtime monitoring -------------------------------------------

  /**
   * Start the runtime monitor: watch the signal stream, run the abuse detectors, surface
   * suspects, and — when a signer is configured — auto-file validator-gated AbuseReports
   * (threading the facade's default author + active-policy-category gate via `reportAbuse`).
   * The monitor NEVER enforces and NEVER auto-slashes.
   * @param {import("./monitor.js").WatchHandlers & { onReport?:Function }} handlers
   * @param {object} [opts]  { detectors?, reportOpts? }
   * @returns {{ close():void }}
   */
  monitor(handlers = {}, opts = {}) {
    return Monitor.watchJobs(
      this.ce,
      {
        onJob: handlers.onJob,
        onError: handlers.onError,
        onSuspect: async (suspect, sig) => {
          try {
            if (handlers.onSuspect) handlers.onSuspect(suspect, sig);
            if (typeof this.signer === "function") {
              const report = await this.reportAbuse(
                {
                  artifact_digest: suspect.sample.artifact_digest,
                  job_id: suspect.sample.job_id,
                  host: suspect.sample.host,
                  category: suspect.finding.category,
                  severity: suspect.finding.severity,
                  evidence: suspect.finding.evidence,
                },
                opts.reportOpts || {},
              );
              if (handlers.onReport) handlers.onReport(report, suspect, sig);
            }
          } catch (e) {
            if (handlers.onError) handlers.onError(e);
          }
        },
      },
      { detectors: opts.detectors },
    );
  }

  /**
   * File a signed, beacon-stamped AbuseReport (category must be in the active set).
   * @param {Partial<import("./types.js").AbuseReport>} fields
   * @param {object} [opts]
   * @returns {Promise<import("./types.js").AbuseReport>}
   */
  reportAbuse(fields, opts = {}) {
    if (typeof this.signer !== "function") {
      throw new TypeError("Governance.reportAbuse requires a signer to be configured");
    }
    return Monitor.reportAbuse(this.ce, this.evidence, this._withAuthor(fields), this.signer, opts);
  }

  /** Collect recent AbuseReports off the signal window. @param {object} [opts] */
  collectReports(opts = {}) { return Monitor.collectReports(this.ce, opts); }

  /**
   * Build the proposed on-chain (bonded-annotation) trigger payload for a report.
   * Never slashes — see docs/onchain-spec.md §2.5.
   * @param {import("./types.js").AbuseReport} report
   * @param {object} [opts]
   */
  slashTriggerPayload(report, opts = {}) { return Monitor.slashTriggerPayload(report, opts); }

  // ---- internal ----------------------------------------------------------

  /** Attach the default author when the caller omitted it. @private */
  _withAuthor(fields) {
    if (this.author && fields && fields.author === undefined) {
      return { ...fields, author: this.author };
    }
    return fields;
  }

  /** Build the options bag for tally/finalizeVerdict with shared deps bound. @private */
  _tallyOpts(opts) {
    return {
      ...opts,
      validator: opts.validator || this.evidence,
      verifySig: opts.verifySig || (this.verifySig ? (p, s, a) => this.verifySig(p, s, a) : undefined),
      allowUnsigned: opts.allowUnsigned ?? this.allowUnsigned,
    };
  }
}

export default Governance;
