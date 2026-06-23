# ce-gov architecture

`@ce-net/gov` is the governance, policy, and abuse-monitoring **app** for CE-net. CE is
primitives-only (`ce/docs/primitives.md`): the node owns generic, node-enforced mechanism and
nothing product-shaped. Governance is policy, voting is product, abuse classification is an
LLM/heuristic judgment — all three are forbidden in the node and belong in an app. This is that app.

It rides five CE primitives and adds **zero** chain or node code (the only chain additions it would
*like* are proposed, not implemented, in `onchain-spec.md`):

| Primitive | API | Used for |
|---|---|---|
| Identity / signatures | Ed25519 node keys, `ce-cap` chains | authorship of every artifact |
| Reputation substrate | `GET /history/:node_id` | computing karma + per-topic expertise |
| Content-addressed data | blobs (pluggable; `ce.js`) | durable, immutable proposals/arguments/verdicts/scan results |
| Messaging | `POST /signals/send`, `GET /signals`, `/signals/stream` | broadcasting and observing artifacts |
| Verifiable randomness | `GET /beacon` | unbiasable sampling of verifiers and (anti-grind) vote provenance |

The unifying object model lives in `src/types.js`: each artifact is a JSON object with a `kind`,
an `author` (64-hex NodeId), a content-addressed `id` (`sha256` over the domain-tagged canonical
payload), and a `sig` (the author's Ed25519 signature over that same payload). Content addressing
makes every artifact a blob CID; signing makes authorship verifiable via `ce-cap` concepts. Money
is always integer base units carried as decimal strings (`Amount` helpers) — never a float.

---

## (a) Pre-run policy scan

> Every process / image / WASM module, before it runs, must be open-source and is scanned by an AI
> against the **active policy set**; the allow/deny verdict is cached by content digest.

This is the **app-side complement** to the node's Guardian (`ce/docs/guardian.md`). The two are
deliberately split, and the seam matters:

### The seam between this app and the node Guardian

The node Guardian (`ce-guard` crate + `ce-guardian` sidecar, being built by another team) is the
**load-bearing enforcement point**: a host refuses to launch banned code regardless of who placed
it, via the `screen_or_reject` chokepoint immediately before `runtime.launch`. The Guardian is
intentionally *content-free* about policy — the node never learns what "pornographic content" or
"cryptomining" means. Its `GuardPolicy.banned_categories` is a per-operator, local, signable list.

`ce-gov`'s scan subsystem (`src/scan.js` + `src/validator.js`) is the **app-side optimization** the
Guardian design explicitly invites (guardian.md §2, "App-side (an optimization)"): the placing app
fetches-or-produces a verdict **before** bidding so a payer does not pay for a placement the host
will refuse anyway. It does three things the node Guardian does not:

1. **Open-source requirement.** A `ScanRequest` carries a `source_url`. The scan refuses to issue
   `allow` for an artifact whose source is not openly available — "is it open-source?" is a policy
   judgment, so it lives here, not in the node.
2. **AI classification against the active policy set.** `src/validator.js` runs deterministic checks
   first (the hard layer, reproducible) and escalates novel/ambiguous artifacts to an LLM
   (`claude-opus-4-8` / `claude-haiku-4-5-20251001`) or CE's own `ce-infer`, behind one adapter.
   The verdict is structured (`ScanVerdict`: decision, categories, confidence, rationale, plus the
   `model_id`/`prompt_template_hash`/`rule_pack_version` provenance the Guardian design requires for
   reproducibility).
3. **Verdict caching by content digest.** A `ScanVerdict` is content-addressed and broadcast as a
   CEP-1 signal. Because both Docker images (pinned digest) and WASM modules (`module_hash`) are
   content-addressed, the verdict is keyed by `artifact_digest` and reused mesh-wide: scan once per
   CID. A cached, still-valid verdict (same `policy_set_id`, same model) short-circuits.

### How the active policy set feeds Guardian's `banned_categories`

The crucial connection: **the active policy set is the output of voting (subsystem c), and it is
what both the app scan and the node Guardian screen against.**

```
                 voting (c)
   proposals + arguments + expert votes
                    │
                    ▼
              signed VERDICT  ──enacts──►  Policy{category, action:'deny', verdict_id}
                                              │
                                              ▼
                        src/policy.js: the ACTIVE POLICY SET
                          (a signed, versioned, content-addressed set of Policy objects)
                          ├──► src/scan.js / validator.js: scan classifies against these categories
                          └──► EXPORT: derive GuardPolicy.banned_categories for the node Guardian
```

`src/policy.js` produces two artifacts from the set of enacted `Verdict`s:

- the **active policy set** (a content-addressed bundle with an `id` = `policy_set_id`, referenced
  by every `ScanRequest`/`ScanVerdict` so a verdict is bound to the exact rules it was scanned
  against — a policy change deterministically invalidates stale verdicts, exactly the Guardian
  cache-invalidation rule); and
- a **`guardPolicyExport()`** that maps the enacted `deny` categories to the
  `GuardPolicy.banned_categories` TOML shape the node Guardian reads. An operator who *opts in* to a
  governance domain points their Guardian at this export. This preserves CE's no-lighthouse
  invariant: the node still enforces only its own operator's policy; `ce-gov` just produces a
  well-formed, signed, community-derived candidate the operator may adopt. Adoption is the
  operator's choice, never imposed by the substrate.

So governance does not bypass the Guardian — it **feeds** it. The Guardian remains the enforcement
seam; `ce-gov` supplies the vocabulary that seam screens against, and that vocabulary is decided by
reputation-weighted expert voting rather than handed down by any authority.

---

## (b) Runtime monitoring

> Monitor running jobs (resource metering, behavior signals, abuse reports for porn / crypto-mining
> / etc.), produce signed abuse reports, feed them into the karma/reputation layer and the
> (proposed) on-chain slashing.

`src/monitor.js` watches the jobs a node runs and the signals on the mesh, and turns observed
abuse into evidence. It does **not** enforce and **never** auto-slashes — consistent with guardian.md
§7 ("CE never auto-slashes from a scan alone — an LLM verdict is not on-chain-provable") and
sybil-resistance.md §4.1 ("Never auto-slash for non-deterministic output correctness").

### Inputs (all from CE primitives)

- **Resource metering / behavior** — derived from job lifecycle facts already on the chain and from
  CEP-1 capacity/heartbeat signals. The monitor correlates a `job_id` and `artifact_digest` with
  the host running it.
- **Abuse reports** — a human or automated observer submits structured evidence (the offending
  `artifact_digest`, `job_id`, host, violated `category`, severity, evidence text). The monitor
  optionally runs the same `validator.js` classifier to attach an AI/heuristic `validator_verdict_id`.

### Output: a signed `AbuseReport`

An `AbuseReport` (see `types.js`) is content-addressed, signed by its reporter, stamped with a
`/beacon` height+hash (provenance, so the report can be shown not to have been crafted against a
cherry-picked chain state), and broadcast as a CEP-1 signal. It references an **active policy
category** — a report is only meaningful against a rule the community enacted (closing the loop with
subsystem c).

### Feeding karma + (proposed) slashing

- **Karma / reputation feed (today, app-tier).** `src/reputation.js` consumes `AbuseReport`s as a
  *negative* signal alongside the immutable `/history` facts, down-weighting repeat-offender hosts
  and payers. This is purely advisory: it biases who the scheduler/voting trusts; it touches no
  consensus path. Reports are **rate-limited and bond-/stake-deterred** (per guardian.md §7 and
  sybil-resistance.md N7b) so a griefer cannot spam false reports to tank a victim's reputation —
  the reporter stakes, and a report contradicted by a higher-tier re-scan forfeits the stake.
- **On-chain slashing (proposed, in `onchain-spec.md`).** An `AbuseReport` is *evidence input* to a
  future `AbuseReport -> Slash` path. Crucially, an LLM verdict is **not** on-chain-provable, so the
  spec proposes slashing only the on-chain-provable fault classes from sybil-resistance.md §4.1
  (equivocation, beacon-challenge miss, failed redundant verification), with the `AbuseReport`
  serving as the human-readable annotation and the trigger for a *redundant re-scan* whose K-of-N
  divergence **is** provable. The app never slashes; it produces the evidence the node team's
  bond/slash machinery can consume.

---

## (c) Governance / voting — "Reddit for experts"

> Proposals (e.g. "ban hosting of pornographic content"), structured arguments as PROOF (pro) and
> ANTI-PROOF (con) requiring external trusted sources, upvote/downvote by experts,
> reputation-weighted tallying, evidence verification, quadratic-ish weighting to resist whales,
> and a published signed VERDICT that becomes active policy.

The flow, end to end:

```
  Proposal ──► Arguments (proof / antiproof, each with required sources)
      │                 │
      │            expert Votes (up/down, reputation-weighted)
      │                 │
      ▼                 ▼
   close_height reached → tally (quadratic-ish, evidence-verified) → signed VERDICT → active Policy
```

### Proposals (`src/proposals.js`)

A `PolicyProposal` states a rule ("ban hosting of pornographic content"), the `category` it would
create/modify, the `action` (`deny`/`allow`), `expertise_tags` (which expertise counts as
authoritative for this topic), and an `open_height`/`close_height` voting window measured in chain
block heights (so the deadline is objective and observable by everyone via `/status`). It is
content-addressed, signed, broadcast, and indexed from the signal stream.

### Arguments as proof / anti-proof (`src/proposals.js`)

An `Argument` is a structured `proof` (supports) or `antiproof` (opposes) attached to a proposal.
**Sources are required**: each `Argument.sources[]` is `{url, title, trust}` — an argument with no
external trusted sources carries zero weight in the tally. "Reddit for experts" means the *evidence*
is first-class, not just the opinion: the debate is a corpus of cited claims that voters and the
validator can check.

### Voting by experts, reputation-weighted (`src/voting.js`, `src/reputation.js`)

Anyone may vote, but a vote's weight is **derived, not declared**: it comes from the voter's
reputation computed by `src/reputation.js` from the immutable `/history` facts (jobs hosted, net
earned, recency, slashes, expiries) and the proposal's `expertise_tags` (a security proposal weights
security expertise). A `Vote` records the raw `weight` and the `/beacon` height+hash sampled at vote
time (anti-grind provenance) and is signed + content-addressed.

### Reputation-weighted, quadratic-ish, whale-resistant tally (`src/voting.js`)

The tally resists three attacks at once:

1. **Sybil splitting** — fresh keys have ~zero reputation (the trust gradient: a stranger starts at
   the bottom), so splitting a stake across many identities buys no extra weight. This inherits CE's
   own Sybil posture: reputation is non-transferable and earned only by real, burn-costly work.
2. **Whale dominance** — raw reputation weight is passed through a **quadratic-ish damping**
   (effective weight `≈ isqrt(raw_weight)` over integer base units, computed with BigInt — never a
   float, so the tally is deterministic and reproducible by any observer). This is the standard
   quadratic-voting whale-resistance result: doubling your reputation does not double your influence.
   The damping is applied per *identity*, which is exactly why pillar 1 (Sybil splitting resistance)
   must hold — quadratic voting amplifies the value of splitting, so it is only safe atop
   reputation-gated identities.
3. **Unsupported opinion** — votes on arguments are scaled by the argument's verified-source weight
   (`src/validator.js` confirms the sources resolve and rates them), so a downvote backed by trusted
   sources outweighs an unsupported one.

The effective `tally_for` / `tally_against` are integer base-unit strings.

### Evidence verification (`src/validator.js`)

The same AI adapter that scans artifacts verifies argument evidence: it checks that cited sources
resolve, rates their trustworthiness, and (with an LLM/`ce-infer`) flags arguments whose body is not
actually supported by their sources. With no `ANTHROPIC_API_KEY` and no `ce-infer`, it degrades to
deterministic checks (URL reachability/format, source-domain trust table) so the tally still runs.

### The signed VERDICT becomes active policy (`src/voting.js` -> `src/policy.js`)

When `close_height` passes, `src/voting.js` produces a `Verdict`: the decision, the effective
tallies, voter count, and the `/beacon` at finalization. The verdict is signed and content-addressed.
If it passes, it enacts a `Policy{category, action, verdict_id}` that `src/policy.js` folds into the
**active policy set** — which is precisely what subsystem (a)'s scan screens against and what
`guardPolicyExport()` hands to the node Guardian. The loop closes: the community decides the rules,
the scan enforces them pre-run, the monitor watches for violations, and the violations feed the
reputation that weights the next vote.

---

## Module contract

Seven modules implement the subsystems; all import `types.js` and `ce.js`. The precise named
exports, signatures, and which shared symbols each uses are in the **module contract** returned to
the orchestrator (and reproduced for implementers below). The contract is designed so the seven can
be built in parallel without collisions: each module owns one file, depends only on `types.js`,
`ce.js`, and (where noted) `reputation.js`/`validator.js`/`policy.js`, and communicates through the
typed artifacts in `types.js` rather than through each other's internals.

| Module | Subsystem | Depends on |
|---|---|---|
| `src/reputation.js` | shared karma/expertise from `/history` | `types.js`, `ce.js` |
| `src/proposals.js` | (c) proposals + arguments | `types.js`, `ce.js` |
| `src/voting.js` | (c) tally + verdict | `types.js`, `ce.js`, `reputation.js`, `validator.js` |
| `src/validator.js` | (a)(b)(c) AI adapter | `types.js` |
| `src/scan.js` | (a) pre-run policy scan | `types.js`, `ce.js`, `validator.js`, `policy.js` |
| `src/monitor.js` | (b) runtime monitoring | `types.js`, `ce.js`, `reputation.js`, `validator.js`, `policy.js` |
| `src/policy.js` | (a)(c) active policy set + Guardian export | `types.js`, `ce.js` |

## Design invariants (carried from CE)

- Integers, never floats, for anything hashed/tallied (BigInt; quadratic damping is integer
  `isqrt`).
- Amounts cross JSON as decimal strings.
- Every artifact is content-addressed and signed; verification is local and offline (`ce-cap`).
- The app never enforces on the host and never auto-slashes; it produces signed evidence and
  signed policy candidates the node/operator chooses to honor.
- No global oracle: the active policy set is a *candidate* the operator opts into, preserving the
  no-lighthouse invariant.
