# On-chain governance — a proposal for the node team

Status: **proposal, not implemented.** This document describes the *minimal* chain/protocol
additions that would make `ce-gov` governance **binding** rather than purely advisory. Nothing here
is built in `ce`; `ce-gov` runs today entirely on existing primitives (signals + blobs + `/history`
+ `/beacon`) with verdicts that operators *opt into*. This spec is the path to making an enacted
verdict change what hosts will *run* without each operator manually editing a TOML file.

**Tone and intent: this extends, it does not replace.** It is built on top of the Guardian seam
(`ce/docs/guardian.md`), the bond+slash machinery (`ce/docs/sybil-resistance.md` §4.1), the
`min(bond, earned-work)` weight oracle and `SlashEquivocation` pattern already implemented on
branch `phase0-settlement-burn` (`ce/docs/consensus.md` §7), and the `ce-cap` capability model. It
reuses those mechanisms wherever possible and proposes new tx types only where a generic mechanism
is genuinely missing. Every design choice respects the CE-vs-app boundary: the node stays generic
and content-free; all human/policy vocabulary stays in `ce-gov`.

---

## 1. What governance needs from the chain, and what it does not

Governance needs exactly three things to become binding:

1. **A canonical, ordered, tamper-evident record** of proposals, arguments, votes, and verdicts, so
   every node computes the *same* tally and the *same* active policy set deterministically. CEP-1
   signals are gossiped and bounded (last-100 window); they cannot give a globally-agreed,
   replay-proof ordering. The chain can.
2. **A deterministic tally + finalization rule** so "this verdict is enacted" is consensus, not one
   app's opinion.
3. **A binding hook** so an enacted policy can (optionally, per operator opt-in) feed the Guardian's
   `banned_categories` and so an `AbuseReport` can trigger the *existing* provable slash paths.

Governance does **not** need: the argument *text*, the LLM rationale, the source list, or the karma
math on-chain. Those stay as content-addressed blobs referenced by hash. The chain stores only the
*minimum* needed for deterministic tallying — keeping CE generic and the blocks small.

The guiding litmus (primitives.md): a key/byte/coin mechanism every governance app would reinvent →
candidate primitive; product semantics (what "pornographic" means, how karma is computed) → stays
in `ce-gov`. Accordingly the proposed tx types carry **opaque** category strings and **content
hashes**, never policy meaning.

---

## 2. Proposed tx types (minimal, generic, opaque)

All follow the existing signed-message + content-hash + idempotent-set patterns already in
`ce-chain` (mirroring `RevokeCapability`'s `(issuer, nonce)` set and `SlashEquivocation`'s
self-contained proof). Amounts are `u128` base units. Each tx is Ed25519-signed by its `origin`.

### 2.1 `PolicyProposal { proposer, proposal_hash, category, open_height, close_height, nonce }`
- `proposal_hash` — `sha256` of the full `PolicyProposal` blob (`ce-gov` `types.js` artifact). The
  chain stores the hash; the body lives as a blob.
- `category` — an **opaque** string (the node never interprets it; it is policy vocabulary). Bounded
  length.
- `open_height`/`close_height` — voting window in block heights. Validity: `open_height >=
  current_height`, `close_height > open_height`, window length within `[MIN, MAX]` bounds.
- Idempotent per `(proposer, nonce)`. Opening a proposal MAY require a small refundable stake
  (an ordinary `Transfer`/lock, no new mechanism) to deter spam — refunded on finalization unless
  the proposal is judged abusive (same pattern as guardian.md §9 appeals).

### 2.2 `Argument { author, proposal_hash, argument_hash, arg_kind, nonce }`
- `argument_hash` — `sha256` of the `Argument` blob (body + required sources). Chain stores only the
  hash + `arg_kind` (`proof`/`antiproof`) for ordering/anchoring; the source list and AI evidence
  verdict stay off-chain.
- Validity: references an open `PolicyProposal` (by `proposal_hash`) within its voting window.

### 2.3 `Vote { voter, proposal_hash, argument_hash?, direction, seed_height, nonce }`
- `direction` — `up`/`down`. `argument_hash` optional (vote on the proposal directly, or on a
  specific argument).
- `seed_height` — the confirmed-depth `/beacon` height the voter sampled (anti-grind provenance;
  must be `<= current_height - LOOKBACK` to prevent grinding the selection, reusing the consensus
  `LOOKBACK=64` discipline from consensus.md §2).
- **The vote carries no weight field.** Weight is *derived deterministically by every node* from the
  weight oracle (§3) at `close_height - LOOKBACK`. This is the load-bearing anti-forgery choice: a
  voter cannot declare its own weight; the chain computes it from already-consensus state.
- Idempotent per `(voter, proposal_hash, argument_hash, nonce)`; a later vote from the same voter on
  the same target supersedes the earlier (last-write-wins within the window).

### 2.4 `PolicyEnact { proposal_hash, verdict_hash, decision, tally_for, tally_against, voter_count }`
- Submittable by **anyone** once `current_height > close_height` (it is a deterministic finalization,
  not a privileged action). The chain **recomputes** `tally_for`/`tally_against` from the recorded
  votes + the weight oracle and **rejects** the tx if the claimed tallies/decision do not match the
  canonical computation. So `PolicyEnact` is self-verifying: a single honest submitter suffices, and
  no dishonest one can enact a false result.
- On accept: records `(category -> decision)` in a chain-tracked **active policy set** map, keyed by
  `category`, superseding any prior enactment for that category. `verdict_hash` anchors the full
  `Verdict` blob.
- This composes with `ce-cap`: enactment MAY additionally require the proposal to be rooted in a
  governance capability domain (an operator/org that has opted into governance lists a governance
  root key), exactly mirroring `accepted_roots`. Operators who do not opt in simply ignore the map.

### 2.5 `AbuseReport -> Slash` — do NOT add a new slash; route to the existing provable paths
An `AbuseReport` (the `ce-gov` artifact) is **evidence**, and an LLM/heuristic verdict is **not
on-chain-provable** (guardian.md §7, sybil-resistance.md §4.1). Therefore:

- **No `SlashAbuse` tx.** Adding one would let a subjective classifier burn a host's bond — exactly
  the griefing/centralization failure the existing design forbids.
- Instead, an on-chain `AbuseReport { reporter, artifact_digest, host, category, report_hash,
  stake, nonce }` is a **bonded annotation**: it records that abuse was alleged and *stakes the
  reporter* (a refundable lock; forfeited if a higher-tier re-scan contradicts it — the
  guardian.md §9 appeal economics). It carries **no slashing power on its own.**
- It can *trigger* the existing provable machinery: a reported `artifact_digest` becomes eligible for
  a `/beacon`-seeded **K-of-N redundant re-scan** (sybil-resistance.md §4.2 T2). The *divergence* of
  that re-scan (minority verdict vs >2/3 supermajority) **is** provable, and feeds the *already-spec'd*
  `SlashVerificationFault` path — not a new one. The node team owns that path; `ce-gov` only supplies
  the report and the scan verdicts.
- Net: governance makes hosts running banned work *reportable and re-scannable*; the bond is at risk
  only through the provable redundant-verification path that already exists, with the
  correlation-penalty honest-host protection intact.

---

## 3. How reputation weight is derived (reuse, do not reinvent)

Vote weight must be deterministic and Sybil-resistant. CE already has the right primitive:
`consensus_weight(node) = min(active_bond, earned_work_score)` (consensus.md §6, Phase 2,
implemented). Governance weight reuses it:

```
gov_weight(voter, h) = quad( min(active_bond(voter), earned_work_score(voter)) )   read at h − LOOKBACK
```

- `earned_work_score` v0 = `NodeStats.earned` (net-of-burn), so washing reputation between
  attacker-owned keys costs the real settlement burn every cycle (the keystone from consensus.md).
- `quad(x)` = **integer** `isqrt(x)` (quadratic-ish whale damping), computed on `u128` base units —
  deterministic, no floats (the Filecoin Dec-2020 non-determinism-halt lesson).
- Per-topic expertise weighting (the proposal's `expertise_tags`) is an **app-tier** refinement and
  stays in `ce-gov` (it requires subjective topic→history mapping). The *chain* tally uses the
  generic `gov_weight`; `ce-gov` may present an expertise-weighted *view*, but the **binding**
  on-chain tally is the generic, reproducible one. This keeps the consensus-critical path free of
  policy vocabulary while still letting the app surface expertise.

This is the bridge sybil-resistance.md §4.3 step 3 already calls for ("import economic Sybil
resistance into" the higher layer): minting N voter keys is free, but earning positive `gov_weight`
requires N bonds + N real-work histories — the only weighting with unbounded Sybil cost.

---

## 4. Finalization and determinism

- **Tally is a pure function** of `{recorded votes in [open,close], weight oracle at close−LOOKBACK,
  argument-anchoring}`. Every node computes it identically; `PolicyEnact` is validated by
  recomputation. No quorum query, no synchronous round-trip (consistent with the VRF/append model).
- **Quorum + threshold** are consensus constants (e.g. `GOV_QUORUM_WEIGHT`, `GOV_PASS_BPS = 6000`):
  a verdict passes iff total participating weight ≥ quorum and `tally_for / (tally_for+tally_against)
  ≥ threshold`. Tunable pre-launch like `SETTLEMENT_BURN_BPS`.
- **Finality** rides the existing `FINALITY_DEPTH` + threshold checkpoint: an enacted policy is
  soft-final at depth and hard-final at the next checkpoint, so a reorg cannot silently un-enact a
  policy hosts are already screening against.
- **Idempotency sets** mirror the existing `revoked`/`slashed` sets: `(proposer,nonce)`,
  `(voter,proposal,argument,nonce)`, enacted-`category` map. O(1) lookups, cache-rebuildable.

---

## 5. How it composes with the Guardian crate + ce-cap

- **Guardian (`ce-guard`):** the on-chain active-policy-set map becomes an *optional source* for an
  operator's `GuardPolicy.banned_categories`. `ce-gov`'s `policy.js guardPolicyExport()` already
  produces the TOML shape from enacted verdicts; with this spec, an operator can instead point the
  Guardian at the **chain-tracked** map (still per-operator opt-in: the node reads the map only if
  the operator configured a governance root, exactly like `accepted_roots`). The Guardian remains
  the sole enforcement seam; governance only supplies the vocabulary. No global ban oracle is
  created — an operator must opt in, preserving the no-lighthouse invariant.
- **ce-cap:** governance authority is expressed as capability chains. The "who may open a binding
  proposal / who is a governance-domain participant" question is answered by `ce-cap` roots, not a
  new ACL — `PolicyProposal`/`PolicyEnact` validity MAY require a chain rooted at a configured
  governance root (mirroring consensus.md §4.1's "human-vetted first widening" of root operators).
  The capability verifier stays content-free: it authorizes the opaque action string
  `governance:propose` / `governance:enact`; it never learns what a category means.

---

## 6. What stays off-chain (the boundary, restated)

| On-chain (proposed, minimal) | Off-chain (`ce-gov` blobs + app) |
|---|---|
| proposal/argument/vote/verdict **hashes** + ordering | proposal/argument **text**, source lists, rationale |
| opaque `category` string + `decision` | what the category *means*, expertise mapping |
| deterministic generic-weight tally | expertise-weighted *presentation* |
| enacted `category -> decision` map | `GuardPolicy` TOML rendering, per-operator adoption |
| bonded `AbuseReport` annotation + stake | AI/heuristic classification, evidence verification |
| reuse of existing bond/slash/checkpoint | the karma scores, the "Reddit for experts" UX |

---

## 7. Summary for the node team

Five small, generic, opaque-payload tx types (`PolicyProposal`, `Argument`, `Vote`, `PolicyEnact`,
bonded `AbuseReport`), a pure deterministic tally that recomputes from the **existing** weight
oracle, finalization on the **existing** checkpoint/finality path, and one optional binding hook
into the **existing** Guardian seam — with **no new slashing power** (abuse routes only through the
already-spec'd provable redundant-verification slash). It adds governance as a thin anchoring +
tally layer over machinery you have already built, and changes nothing about how a host enforces:
the host still runs only what its own Guardian + `ce-cap` allow. We would value your review of (a)
the tx-type minimality, (b) whether `PolicyEnact`-by-recomputation is the cleanest self-verifying
finalization, and (c) the cleanest way to expose the enacted map to `GuardPolicy` without coupling
the node to any policy vocabulary.
