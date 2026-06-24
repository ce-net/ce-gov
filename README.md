# @ce-net/gov

Governance, policy, and abuse-monitoring for **CE-net** — the BFT compute mesh.

CE is **primitives-only**: it owns generic, node-enforced mechanism (identity, money, the
content history, mesh transport, capability verification). Governance, policy decisions, voting,
and abuse classification are **policy**, so they live in an *app*. This is that app.

`@ce-net/gov` is pure, zero-dependency **vanilla JavaScript** (ES modules) that talks to a local
CE node over its HTTP API (`http://localhost:8844`), persists artifacts as content-addressed
**mesh blobs**, broadcasts/observes them over **mesh pubsub**, and serves catch-up queries via a
**DHT-advertised mesh service** — no centralized backend (see "A real mesh app" below). It runs
in both Node (>=18, native `fetch` + Web Crypto) and the browser.

> Status: integrated. The data model, CE client, the seven subsystem modules, a single
> `Governance` facade (`src/index.js`), and runnable offline examples (`examples/`) are in
> place and self-tested. Every module ships a network-free self-test; the examples run
> end-to-end against an in-memory CE + a deterministic signer with no key and no node.

---

## The three subsystems

CE-net needs an app that answers three questions about the work running on the mesh: *should this
be allowed to run? is what is running behaving? and who decides the rules?* `@ce-net/gov` is those
three, in one app, sharing one reputation layer.

### 1. Pre-run policy scan (`src/scan.js`, `src/validator.js`)
Every process / image / WASM module, **before it runs**, must be open-source and is scanned by an
AI against the **active policy set**. The scan returns an allow/deny verdict, signed and cached by
the artifact's content digest (scan once per CID, reuse mesh-wide). This is the **app-side
complement** to the node's Guardian (`ce/docs/guardian.md`): the node enforces; this app decides
*what* the active banned-category vocabulary is — and that vocabulary is the output of voting.

### 2. Runtime monitoring (`src/monitor.js`)
Watches running jobs — resource metering, behavior signals, and human/automated abuse reports
(porn, crypto-mining, etc.). It produces **signed abuse reports**, feeds them into the karma /
reputation layer, and surfaces them as evidence for the (proposed) on-chain slashing path. It
never auto-slashes; an AI/heuristic verdict is advisory, exactly as the Guardian design requires.

### 3. Governance / voting (`src/proposals.js`, `src/voting.js`, `src/policy.js`)
"Reddit for experts." Anyone may open a **proposal** ("ban hosting of pornographic content").
Arguments are structured as **PROOF** (pro) and **ANTI-PROOF** (con), each requiring external
trusted sources. Experts **upvote / downvote**; tallies are **reputation-weighted** (derived from
CE's immutable `/history` facts) with **quadratic-ish** weighting to resist whales, and evidence
is verified. The outcome is a published, signed **VERDICT** that becomes the **active policy set**
that subsystem 1 enforces.

---

## Architecture at a glance

The three subsystems share one reputation layer and one active policy set. Voting decides the
rules; the pre-run scan and the node Guardian enforce them; the monitor watches for violations;
the violations feed the reputation that weights the next vote. The loop closes.

```
                              ┌──────────────────────────────────────────────┐
                              │            CE node (primitives only)          │
                              │  /history  /beacon  /signals*  blobs  ce-cap  │
                              │            Guardian seam (ce-guard)           │
                              └───────▲───────────────▲──────────────▲────────┘
                                      │ facts/IO      │ signals/blobs │ banned_categories
                                      │               │               │  (operator opt-in)
   ┌──────────────────────────────────────────────────────────────────────────────────┐
   │                          @ce-net/gov  (this app, JS)                               │
   │                                                                                    │
   │   reputation.js  ──karma/expertise/weight──┐                                       │
   │        ▲ /history                          │                                       │
   │        │                                   ▼                                       │
   │  (c) proposals.js ─► voting.js ─tally─► VERDICT ─► policy.js ─► ACTIVE POLICY SET   │
   │            ▲  arguments      ▲ quadratic, evidence-gated          │   │            │
   │            │  (proof/anti)   │                                    │   └─ guardPolicyExport()
   │            └─ validator.js ◄─┘  (LLM / ce-infer / deterministic)  │       → node Guardian
   │                    ▲                                              ▼                 │
   │  (a) scan.js ──────┘  pre-run: digest ─► cached ALLOW/DENY ScanVerdict             │
   │                                                                                    │
   │  (b) monitor.js  watch jobs ─► detect abuse ─► signed AbuseReport ─► reputation     │
   │                                            (never enforces, never auto-slashes)     │
   │                                                                                    │
   │  index.js  =  Governance facade  (DI: ce client + signer + verifySig + llm)        │
   └──────────────────────────────────────────────────────────────────────────────────┘
```

The active policy set is the *output of voting* and the *input to both the app scan and the node
Guardian's `banned_categories`* — adoption stays per-operator opt-in (no global ban oracle), so
CE's no-lighthouse invariant holds. See `docs/architecture.md` for the full design.

## How it rides CE primitives

| This app needs | CE primitive used | Where |
|---|---|---|
| Author identity / signatures | Ed25519 node keys; `ce-cap` chains | every signed artifact |
| Immutable reputation facts | `GET /history/:node_id` (NodeStats) | `src/reputation.js` |
| Durable, content-addressed artifacts | mesh **blobs** (`POST /blobs`, `GET /blobs/:cid`, DHT-replicated) | `src/ce.js` (`httpBlobStore`) |
| Broadcast + observe artifacts | mesh **pubsub** on `ce-gov.events.v1` (`/mesh/publish` + `/mesh/subscribe` + `/mesh/messages/stream`) | `src/mesh.js` |
| Catch-up / cross-node queries | DHT-advertised **service** `ce-gov.v1` + request/reply (`/discovery/*`, `/mesh/request`, `/mesh/reply`) | `src/mesh-service.js` |
| Bonded abuse evidence (kept on CEP-1) | CEP-1 signals (`POST /signals/send`, `GET /signals`) — chain-anchored evidence only | `src/monitor.js` |
| Unbiasable randomness (verifier/expert sampling) | `GET /beacon` | `src/ce.js`, `src/voting.js` |
| Money is integer base units | amounts are decimal strings, never floats | `src/types.js` |

The app **computes** reputation/expertise from the raw facts CE guarantees — there is no karma
number on-chain by design. See `docs/architecture.md` for the full design.

---

## A real mesh app (no centralized backend)

`@ce-net/gov` is a **mesh-native** app. The owner's rule: an app registers a frontend with
`ce-app` and exposes ONLY the frontend's domain over HTTP; everything else — app state and
device-to-device communication — rides the **mesh**. The only HTTP this app's own code touches
is its **LOCAL** node at `http://127.0.0.1:8844` (the designed SDK boundary), which routes over
libp2p. There is **no app-owned HTTP server and no central DB** — in particular, none of the
hub's centralized in-memory `/db` (KV) or `/rt` (rooms). See
`/Users/07lead01/ce-net/PLAN/mesh-apps.md` for the full design and the verified API surface.

Three concerns, three mesh primitives:

| Concern | Mesh primitive | Node route | Module |
|---|---|---|---|
| **State** (durable data) | content-addressed **blobs**, DHT-replicated | `POST /blobs`, `GET /blobs/:cid` | `src/ce.js` `httpBlobStore` / `meshPutBlob` / `meshGetBlob` |
| **Events** (live changes) | **pubsub** on the app topic | `POST /mesh/publish` + `/mesh/subscribe` + `GET /mesh/messages/stream` | `src/mesh.js` `announce` / `watchEvents` |
| **Queries** (ask a peer) | **request/reply** to a DHT-advertised service | `/discovery/advertise` + `/discovery/find/:svc` + `/mesh/request` + `/mesh/reply` | `src/mesh-service.js` |
| **Frontend** (the only public HTTP) | static bundle on `ce-app` | `https://<id>.ce-net.com/` | `web/` |

### Names the network agrees on

- **Pubsub topic** `ce-gov.events.v1` (`GOV_TOPIC`) — carries small JSON *index events*
  `{ type, id, cid, height }` where `type ∈ {proposal, argument, vote, verdict, policy}`, `cid`
  is the blob to `GET`, and the blob is the source of truth (the event is the live-feed /
  cache-invalidation signal). Scoped sub-topics `gov/proposals` and `gov/votes` also exist.
- **DHT service** `ce-gov.v1` (`GOV_SERVICE`) — answers `op:"index"` (catch-up) and `op:"get"`
  (fetch an artifact by cid) so a fresh node can back-fill without scanning anything central.
- **Validator service** `gov/validator` (`GOV_VALIDATOR_SERVICE`) — answers `op:"validate"` by
  running `validator.js` + `reputation.js`, so a node without the validator stack (e.g. a
  browser node) can borrow a full node's judgment over the mesh via request/reply.

### Blobs, not `/db`; pubsub, not `/rt` (the cheat that was removed)

The previous design leaned on **CEP-1 signals as an ad-hoc event bus** (broadcasting an index
entry as a signal, re-resolving on every signal) and a **stub blob store**. Signals are bonded,
chain-anchored, and capped at a 100-entry window — the wrong tool for a live app event bus. The
mesh-native swap, one-to-one:

| Old (cheat) | Mesh-native replacement | Node route |
|---|---|---|
| stub/`signalBlobStore` artifact store | immutable, sha256-named **blob** | `POST /blobs` / `GET /blobs/:cid` |
| index entry broadcast as a CEP-1 signal | **publish** `{type,id,cid,height}` on `ce-gov.events.v1` | `/mesh/publish` |
| re-resolve on every `GET /signals` | **subscribe** + SSE of inbound mesh messages | `/mesh/subscribe` + `/mesh/messages/stream` |
| "scan `GET /signals` to find artifacts" | **discover** a service, **request** its index | `/discovery/find/ce-gov.v1` + `/mesh/request` |

CEP-1 signals are **kept** for exactly one thing: bonded `AbuseReport` evidence in
`src/monitor.js`, which must be chain-anchored. Discovery and the live index moved to the mesh.

The `blobStore` still defaults to `memoryBlobStore()` so offline tests/examples stay
deterministic and network-free; pass `httpBlobStore(ce)` (as `index.js` does in production) to
go live on the real `/blobs` route.

### Run the backend mesh service

The long-running governance participant is `src/mesh-service.js`. It advertises the service
names, subscribes the topics, rebuilds a local index from announced CIDs, and serves
`index`/`get`/`validate` over request/reply — all against the **local** node only:

```js
import { CeClient, httpBlobStore } from "./src/ce.js";
import { startGovService } from "./src/mesh-service.js";

const ce = new CeClient({
  base: "http://127.0.0.1:8844",
  token: process.env.CE_API_TOKEN,        // cat ~/.local/share/ce/api.token
});
ce.blobStore = httpBlobStore(ce);          // real /blobs route

const svc = await startGovService(ce, { /* llm, trustOf, verifySig optional */ });
// svc.serviceNames -> ["ce-gov.v1","gov/validator"]; svc.topics -> ["ce-gov.events.v1", ...]
// svc.index()  -> current id->event index;  svc.stop() to shut down.
```

A peer catches up / queries over the mesh (no direct HTTP between app processes):

```js
import { fetchIndex } from "./src/mesh.js";
import { requestValidation } from "./src/mesh-service.js";

const index = await fetchIndex(ce);                 // find ce-gov.v1 + request its index
const verdict = await requestValidation(ce, argument); // find gov/validator + validate over the mesh
```

`examples/mesh-roundtrip.js` runs the whole flow (create -> announce -> live materialize ->
request/reply catch-up) against the in-memory mesh model, and is the template for a true
two-node run against live nodes.

### Deploy the frontend with `ce-app` (the only public HTTP)

The static policy UI under `web/` is the frontend. It talks only to the page's **local** node
(loopback `http://127.0.0.1:8844`, or the browser-node bridge the hub injects), reading the live
feed from `GET /mesh/messages/stream` filtered to `ce-gov.events.v1` and materializing artifacts
via `GET /blobs/:cid`. Deploy it with `ce-app` (used **as-is** — do not modify it):

```bash
# from ce-gov/ — builds the web/ bundle and serves it at https://<id>.ce-net.com/ (and /apps/<id>/)
ce-app deploy            # see ./deploy-frontend.sh for the exact invocation this repo uses
```

There is no backend compute on the hub — which is exactly why state/events ride the mesh, not a
hub DB. The hub's only legitimate roles are serving static frontends (`ce-app`) and relay/
bootstrap for browser nodes that cannot speak libp2p directly.

## How voting drives the pre-run scan and the Guardian

1. A `PolicyProposal` ("Ban hosting of pornographic content") opens with an `open_height`/
   `close_height` voting window and `expertise_tags`.
2. `Argument`s (PROOF / ANTI-PROOF) attach, each citing required trusted sources; `validator.js`
   scores their evidence (deterministic, optionally LLM-escalated).
3. Experts vote; `voting.js` tallies with **reputation weight derived from `/history`**, damped
   **quadratically** (integer `isqrt`, never floats) to resist whales, with verified arguments
   folded in. Quorum + supermajority decide.
4. On pass, a signed `Verdict` is finalized and `policy.js` **enacts** it into a `Policy` that folds
   into the **active policy set** (deterministic `policy_set_id`).
5. `scan.js` screens each artifact **against that active set** before it runs: a deterministic hard
   layer (miner/stratum/scanner/porn signatures, open-source guard) short-circuits to DENY; novel
   artifacts escalate to the LLM; **fail-closed** if no verdict can be produced. Verdicts are cached
   by `(artifact_digest, policy_set_id)` — a policy change invalidates stale verdicts.
6. `policy.js guardPolicyExport()` renders the enacted `deny` categories into the node Guardian's
   `GuardPolicy.banned_categories` shape (`ce/docs/guardian.md` §5), which an opted-in operator
   points their Guardian at. The Guardian remains the load-bearing enforcement seam; governance
   only supplies the vocabulary it screens against.

---

## Quick start

No build step, no install, zero dependencies. Node >= 18 (native `fetch` + Web Crypto).

```bash
# Syntax-check every module + example
npm run check

# Run every module's network-free self-test
npm run selftest

# Run all four runnable demos offline (in-memory CE + deterministic signer, no key, no node)
npm run examples
#   examples/propose-ban-porn.js  open the "ban porn" proposal + a proof + an antiproof
#   examples/tally-demo.js        reputation-weighted, quadratic-damped tally -> signed verdict
#   examples/scan-demo.js         screen a fake xmrig miner (hard-deny) and a benign image
#   examples/monitor-demo.js      detect a hashing-loop job -> signed AbuseReport (no slash)
```

Against a live node, point at it and supply identity + (optional) AI:

```bash
export CE_API=http://localhost:8844                         # defaults to this
export CE_API_TOKEN="$(cat ~/.local/share/ce/api.token)"    # for mutating calls
export ANTHROPIC_API_KEY=sk-ant-...                         # optional; deterministic checks always run
```

### Programmatic use — the `Governance` facade

`src/index.js` re-exports every module's public API and a single dependency-injected
`Governance` facade that wires reputation + proposals + voting + validator + scan + monitor +
policy over one CE client and one LLM adapter:

```js
import { Governance, CeClient } from "./src/index.js";

const gov = new Governance({
  ce: new CeClient(),                                // src/ce.js (HTTP) — or any compatible client
  signer:    async (payload) => signWithNodeKey(payload),     // (payload) => 128-hex Ed25519 sig
  verifySig: async (payload, sig, author) => verify(payload, sig, author),
  // llm omitted => deterministic-only; pass makeValidatorLlm()/makeScanValidator() for Claude/ce-infer
});

const proposal = await gov.createProposal({ title: "...", category: "pornographic_content", action: "deny", expertise_tags: ["legal"] });
await gov.argue({ proposal_id: proposal.id, arg_kind: "proof", body: "...", sources: [{ url, title, trust: 90 }] });
await gov.vote({ proposal_id: proposal.id, direction: "up" });    // weight derived from /history
const verdict = await gov.finalize(proposal);                     // after close_height
await gov.enact(verdict, proposal);                               // -> active policy set
const v = await gov.scanArtifact({ artifact_digest, source_url, cmd /* ... */ });  // pre-run scan
gov.monitor({ onSuspect, onReport });                            // runtime monitoring
```

The LLM call sits behind a small adapter (`src/validator.js` for arguments, `src/scan.js` for
artifacts) that also targets CE's own distributed inference (`ce-infer`); with no key configured the
deterministic checks still run and the app degrades gracefully.

---

## Layout

```
ce-gov/
├── package.json            name @ce-net/gov, type module, no deps; check/selftest/examples scripts
├── README.md               this file
├── docs/
│   ├── architecture.md     full design of the three subsystems + the module contract
│   └── onchain-spec.md     proposal FOR THE NODE TEAM: minimal chain additions to bind governance
├── examples/               runnable, offline, no-key, no-node demos
│   ├── _mock.js            in-memory CeClient + deterministic demo signer + scripted LLM stubs
│   ├── propose-ban-porn.js open the "ban porn" proposal with a proof + an antiproof
│   ├── tally-demo.js       weighted, quadratic-damped tally -> signed verdict -> enacted policy
│   ├── scan-demo.js        screen a fake xmrig miner (hard-deny) and a benign image (allow)
│   ├── monitor-demo.js     detect a hashing-loop job -> signed AbuseReport -> reputation feed
│   └── mesh-roundtrip.js   create -> announce (pubsub) -> materialize (blob) -> request/reply catch-up
└── src/
    ├── index.js            public entry: re-exports all modules + the Governance facade
    ├── types.js            shared data model: factory fns + frozen JSON schemas + canonical hash
    ├── ce.js               zero-dep CE HTTP client (history, signals, blobs, mesh pubsub/req-reply/DHT, beacon)
    ├── mesh.js             mesh transport: GOV_TOPIC/GOV_SERVICE, announce/watchEvents/fetchIndex helpers
    ├── mesh-service.js     the backend mesh service: advertise + subscribe + serve index/get/validate
    ├── reputation.js       compute expertise/karma from /history facts
    ├── proposals.js        create/load proposals + arguments (proof / anti-proof)
    ├── voting.js           reputation-weighted, quadratic-ish, whale-resistant tally + verdict
    ├── validator.js        LLM/ce-infer adapter (graceful-degrade) for AI validation
    ├── scan.js             pre-run policy scan: digest -> cached allow/deny verdict
    ├── monitor.js          runtime monitoring + signed abuse reports
    └── policy.js           the active policy set: derive from verdicts, feed Guardian categories
```

## Node-team handoff

`ce-gov` runs **today** entirely on existing CE primitives, with enacted verdicts that operators
*opt into*. To make governance **binding** — so an enacted verdict changes what hosts will *run*
without each operator manually editing a TOML file — see **`docs/onchain-spec.md`**. It proposes
five small, generic, opaque-payload tx types (`PolicyProposal`, `Argument`, `Vote`, `PolicyEnact`,
a bonded `AbuseReport`), a pure deterministic tally that recomputes from the **existing**
`min(bond, earned-work)` weight oracle, finalization on the **existing** checkpoint/finality path,
and one optional binding hook into the **existing** Guardian seam — with **no new slashing power**
(abuse routes only through the already-spec'd provable redundant-verification slash). It extends; it
does not replace.

Authorship is the user's: Leif Rydenfalk <ledamecrydenfalk@gmail.com>. No co-authors. No emojis.
