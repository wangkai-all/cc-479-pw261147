# Retention & Erasure Console

A multi-tenant data-lifecycle console that enforces per-layer retention, honours
legal holds and statutory minimums, executes verifiable deletion, and proves the
result without ever exposing the data it deleted.

Zero runtime dependencies: Node's built-in `node:sqlite`, `node:http`, and a
vanilla ES-module front end. Node **>= 22.5** (for `node:sqlite`).

```bash
npm start          # http://127.0.0.1:4319 (seeds demo tenants on first run)
npm run seed       # seed / top up tenants
npm run reset      # wipe and reseed
npm run demo       # scripted end-to-end walkthrough, no server needed
npm test           # 34 unit + integration tests
```

## What it does

### Layers, windows and exceptions

Four layers have independent retention windows, per tenant:

| Layer | Holds | Default window (demo tenant) |
|---|---|---|
| `raw` | events as received | 30 days |
| `detail` | enriched records with PII | 400 days, **365-day statutory floor** |
| `summary` | subject-level rollups | 730 days |
| `cache` | rebuildable derived state | 3 hours |

Policies are **versioned and append-only**. A new version is written on every
change; existing manifests keep the version they were generated against. The
API refuses a retention window shorter than the layer's statutory minimum, so a
routine sweep can never delete legally protected records.

Two kinds of exception:

- **Statutory minimum** — a property of the policy. Objects younger than the floor
  survive an erasure request even when the subject asks for deletion.
- **Legal hold** — ad-hoc, scoped to a tenant, a subject, or a date range, with an
  optional layer narrowing and an optional expiry. Holds outrank policy.

### Scope inventory (manifest)

Every deletion request first freezes its scope into an **immutable manifest**:
one row per object with an opaque ref, its timestamp, the *names* of the fields
it carries (never the values), and the blocking decision. The manifest is
canonical-JSON hashed; that hash is recorded on the request and re-checked by
verification, so the scope cannot be edited after the fact.

### Progress and execution

Execution moves layer by layer in batches of 100. Each batch is its own
transaction: rows are deleted and a **keyed content commitment** for each is
written in the same commit, so there is never a moment where an object is gone
but unaccounted for. Batches are chained (`prevRoot` → `commitmentRoot`) and
progress is durable if the process dies mid-request. Re-running a failed or
blocked request re-evaluates the remaining items against current holds.

### Fencing: deleted data cannot come back

This is enforced in the **database**, not the application:

- A **watermark fence** records the cut-off per layer. Triggers on every warehouse
  table abort any insert/update whose timestamp falls at or below that cut-off.
- A **subject fence** records the erased generation per subject. Writes for that
  subject at or below the generation are aborted. A **consent renewal** raises the
  generation and lifts the fence, so a returning subject can be re-onboarded
  without reopening the erased range.

Fences only ever tighten (max cut-off, max generation). A collector that bypasses
the ingestion API entirely still gets `FENCED_RANGE` from SQLite. Rejected writes
are logged as tokenised rejections and surfaced in the UI.

### Proof of deletion

Each completed request issues a proof bundle:

- **Content commitments** — HMACs over the deleted content under a per-tenant
  secret key. They prove which objects were removed without revealing any
  subject identifier, amount, or payload. Being keyed, they also resist offline
  dictionary attacks against a guessed value.
- **Merkle root** over all commitments, with per-batch chained roots and sampled
  inclusion paths.
- **Exceptions** — every blocked item with its reason and the hold that caused it.

Verification re-runs ten checks: proof-document hash, manifest binding, count
reconciliation, **objects-absent** (are the deleted rows really gone?),
Merkle root, sampled inclusion paths, key binding, active fences, **no-reentry**
(is anything now sitting inside a cleared range that the request doesn't
account for?), and the tenant audit hash chain.

### Audit trail

Per-tenant append-only hash chain (DB triggers block UPDATE/DELETE). Payloads
carry opaque tokens, counts and reasons only — never plaintext identifiers or
field values. A mutation anywhere in the chain breaks verification.

## UI

Four views, all against live API data:

- **Overview** — KPI tiles; a per-layer stacked meter (eligible / blocked /
  retained) with hover values; a blocker roll-up explaining *why* objects are
  held; recent requests; and the ingestion-rejection feed showing the fence
  working.
- **Requests & proofs** — request list, per-layer progress, blocker summary,
  proof summary, one-click verify with per-check results, and a downloadable
  proof bundle.
- **Policies** — editable versions with inline validation, plus legal holds with
  release.
- **Audit trail** — the chain with its verification banner.

Light/dark themes are both hand-picked (not an auto-invert). The categorical
palette is validated for colour-blind separation. Charts carry a legend and
printed values, so colour never carries meaning alone.

## API sketch

All routes are under `/api`, scoped by tenant. `x-actor` names the operator.

```
GET    /api/tenants
GET    /api/tenants/:t/overview
GET    /api/tenants/:t/pending                  # dry-run sweep scope + blockers
GET    /api/tenants/:t/policies
PATCH  /api/tenants/:t/policies/:layer          # new version
GET    /api/tenants/:t/holds
POST   /api/tenants/:t/holds
POST   /api/tenants/:t/holds/:id/release
POST   /api/tenants/:t/subjects/inspect         # dry-run subject scope
POST   /api/tenants/:t/requests                 # {kind, layers?, subjectRef?, execute?}
GET    /api/tenants/:t/requests
GET    /api/tenants/:t/requests/:id
GET    /api/tenants/:t/requests/:id/manifest
POST   /api/tenants/:t/requests/:id/execute
GET    /api/tenants/:t/requests/:id/proof
POST   /api/tenants/:t/requests/:id/verify
POST   /api/tenants/:t/ingest                   # {events:[…]} — fenced
GET    /api/tenants/:t/rejections
POST   /api/tenants/:t/consent                  # raises generation
GET    /api/tenants/:t/audit
```

## Layout

```
src/
  schema.sql     tables, fence triggers, append-only audit triggers
  db.js          connection, migration, transaction helper
  crypto.js      tenant keys, subject tokens, commitments, Merkle tree
  policy.js      retention cut-offs, holds, blocker resolution, layer scans
  erasure.js     manifests, execution, fences, proof build & verification
  services.js    tenants, policies, holds, consent, ingestion, overview
  requests.js    request detail views
  server.js      HTTP router + static files
public/          index.html, styles.css, app.js
scripts/         seed.js, demo.js
test/            erasure.test.js (unit), api.test.js (HTTP)
```

## Guarantees and limits

Holds:

- Fence enforcement survives an application bypass — it is database triggers.
- Proofs reveal no erased values; only opaque refs and keyed commitments.
- A policy can never undercut its statutory floor.
- A hold placed after a manifest is generated still blocks execution.

Deliberately out of scope (single-process demo):

- Authentication. `x-actor` is a header, not identity; there is no per-operator
  authorisation or CSRF protection.
- The per-tenant proof key is stored beside the data. In production it belongs in
  a KMS/HSM, and the master secret must not live in the same trust domain as the
  database.
- Merkle paths are stored for a sample of leaves, not all of them; the full leaf
  set is still committed by the root.
