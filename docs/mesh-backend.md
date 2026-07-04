# ce-gov mesh backend

ce-gov is a **real mesh app**: the only HTTP it exposes is its static frontend (`web/`,
deployed via `ce-app` — see `deploy-frontend.sh`). All app state and all device-to-device
communication ride the CE mesh, reached through each participant's **local node** HTTP API
(`http://127.0.0.1:8844`, the designed SDK boundary), which routes over libp2p. There is no
app-owned backend, no central database, and no use of the hub's `/db` or `/rt`.

This doc specifies the three mesh primitives ce-gov uses, the service/topic names, and the
event schema. Source of truth for the node routes is `PLAN/mesh-apps.md` §1.

## Three concerns, three primitives

| Concern | Primitive | Node route | ce-gov module |
|---|---|---|---|
| **State** (durable artifacts) | content-addressed blobs, DHT-replicated | `POST /blobs`, `GET /blobs/:cid` | `httpBlobStore` in `src/ce.js`; written by `proposals.js`/`voting.js`/`policy.js` |
| **Events** (live changes) | pub/sub on a topic | `POST /mesh/publish` + `/mesh/subscribe` + `GET /mesh/messages/stream` | `announce` / `watchEvents` in `src/mesh.js` |
| **Queries** (catch-up / validate) | request/reply to a DHT service | `/discovery/advertise` + `/discovery/find/:svc` + `/mesh/request` + `/mesh/reply` | `fetchIndex` / `requestValidation` (`src/mesh.js`, `src/mesh-service.js`) |

The blob store is the **source of truth** (immutable, sha256-named, self-verifying). Pubsub
is the **live feed / cache-invalidation**. The service is the **catch-up + validator query**
endpoint. Nothing is centralized.

## Service names (DHT)

| Name | Constant | Purpose |
|---|---|---|
| `ce-gov.v1` | `GOV_SERVICE` | generic governance query service: answers `index` (the discovery index) and `get` (an artifact by cid). A fresh node `find`s a provider and `request`s its index to catch up. |
| `gov/validator` | `GOV_VALIDATOR_SERVICE` | argument-validation service: answers `validate` by running `validator.js` (+ `reputation.js`) and replying the `ArgumentValidation` verdict. Lets a thin client (e.g. a browser) borrow a full node's judgment. |

A node running `startGovService(ce)` (`src/mesh-service.js`, or `Governance.start()`)
advertises **both** and re-advertises on an interval (DHT records expire).

## Topics (pub/sub)

| Topic | Constant | Carries |
|---|---|---|
| `ce-gov.events.v1` | `GOV_TOPIC` | the governance event bus — index events for proposals, arguments, votes, verdicts, and policies. |
| `gov/proposals` | `TOPIC_PROPOSALS` | scoped proposal events (the service also subscribes; subset consumers may scope to it). |
| `gov/votes` | `TOPIC_VOTES` | scoped vote events. |

## Event schema

Every announcement on a governance topic is the small immutable JSON **index event**:

```json
{ "type": "proposal", "id": "<64hex artifact id>", "cid": "<64hex blob cid>", "height": 12345 }
```

| Field | Meaning |
|---|---|
| `type` | one of `proposal` \| `argument` \| `vote` \| `verdict` \| `policy` (`EV.*` in `src/mesh.js`). |
| `id` | the artifact's content id (`sha256` over its domain-tagged signing payload; from `types.js finalize`). |
| `cid` | the blob cid to `GET /blobs/:cid` to materialize the full artifact (`sha256` of the stored JSON bytes — distinct from `id`). |
| `height` | chain-height provenance (open height for proposals, beacon height for votes/verdicts, ts for policies). |

The payload on the wire is `hex(JSON.stringify(event))` (`encodeJsonHex`). Subscribers decode
it (`decodeEvent`), update their local id→cid index, and `GET /blobs/:cid` on demand. The
event intentionally carries no business fields — the blob is authoritative, so a tampered
event cannot misrepresent an artifact (the cid self-verifies).

## Request/reply envelopes (to a service)

Requests to `GOV_SERVICE` / `GOV_VALIDATOR_SERVICE` are `hex(JSON.stringify({ op, ... }))`:

| `op` | Request | Reply |
|---|---|---|
| `index` | `{ op:"index" }` | `{ index: IndexEvent[] }` |
| `get` | `{ op:"get", cid }` | `{ artifact: <artifact JSON or null> }` |
| `validate` | `{ op:"validate", argument }` | `{ validation: ArgumentValidation }` or `{ error }` |

The service answers an inbound request (an `AppMessage` carrying a `reply_token`) by
`POST /mesh/reply` with the same `reply_token`. Unknown ops always get a `{ error }` reply
so a caller's `/mesh/request` never hangs to its timeout.

## Data flow (write → live → catch-up)

1. **Write.** A module builds an immutable artifact, `POST /blobs` (→ `cid`), then `announce`
   publishes `{type,id,cid,height}` on `GOV_TOPIC`.
2. **Live.** Subscribers receive the event on `GET /mesh/messages/stream`, index it, and
   `GET /blobs/:cid` to materialize — the basis of the frontend live feed.
3. **Catch-up.** A fresh node `find`s a `ce-gov.v1` provider and `request`s `{op:"index"}`,
   then back-fills artifacts by cid. No central store is consulted.

See `examples/mesh-roundtrip.js` for the full create → announce → live materialize →
request/reply catch-up sequence (two simulated nodes; the same code runs against live nodes).

## What stays on CEP-1 signals (deliberately)

`monitor.js` `AbuseReport` remains a **CEP-1 signal**: bonded, chain-anchored evidence whose
correct home is the chain, not the live app event bus. Everything else moved to the mesh.

## Backward compatibility

The mesh backend is **opt-in and additive**. `CeClient`'s default `blobStore` is still the
in-memory store, so the offline `__selftest`s and examples run with no node. Pass
`httpBlobStore(ce)` (or `new Governance({ ce, mesh: true })`) to go live. Discovery/event
calls auto-detect: when the ce client exposes `/mesh/*` they use the mesh; a mesh-less client
falls back to the legacy CEP-1 signal index so nothing regresses.

## Frontend

`web/index.html` probes its local node for `/mesh/*` at boot (`detectMesh`). If present it
switches to the real `/blobs` store and the `GOV_TOPIC` pubsub feed; otherwise it falls back
to the signal-backed store. Browser users reach the mesh through their **own local node**
(loopback) or a browser-node bridge / gateway — the page never embeds a token or POSTs to a
foreign node. Mutating calls (blob PUT, publish) carry the local node's `api.token`, supplied
by the bridge (or `?token=` on a loopback dev node).
