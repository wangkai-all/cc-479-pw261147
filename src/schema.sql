-- Retention & erasure console - schema
-- All timestamps are integer milliseconds since the Unix epoch.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- ---------------------------------------------------------------------------
-- Tenancy & policy
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenants (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  region        TEXT NOT NULL,
  description   TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL
);

-- Per-tenant key material. The key itself is never returned by any API:
-- it is used for HMAC subject tokens and content commitments, so audit
-- evidence cannot be dictionary-attacked offline. Only the fingerprint ships.
CREATE TABLE IF NOT EXISTS tenant_keys (
  tenant_id      TEXT PRIMARY KEY REFERENCES tenants(id),
  proof_key      TEXT NOT NULL,
  key_fingerprint TEXT NOT NULL,
  created_at     INTEGER NOT NULL
);

-- Versioned retention policy. One current row per tenant + layer.
CREATE TABLE IF NOT EXISTS retention_policies (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants(id),
  layer           TEXT NOT NULL CHECK (layer IN ('raw','detail','summary','cache')),
  retention_value INTEGER NOT NULL,
  retention_unit  TEXT NOT NULL CHECK (retention_unit IN ('hours','days')),
  legal_basis     TEXT NOT NULL,
  exception_note  TEXT NOT NULL DEFAULT '',
  -- Statutory minimum age before an object may be removed even on request.
  -- 0 means the layer has no statutory floor.
  statutory_min_days INTEGER NOT NULL DEFAULT 0,
  statutory_basis    TEXT NOT NULL DEFAULT '',
  version         INTEGER NOT NULL,
  is_current      INTEGER NOT NULL DEFAULT 0,
  effective_from  INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (tenant_id, layer, version)
);
CREATE INDEX IF NOT EXISTS ix_policy_current
  ON retention_policies (tenant_id, is_current);

CREATE TABLE IF NOT EXISTS legal_holds (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL REFERENCES tenants(id),
  scope_kind    TEXT NOT NULL CHECK (scope_kind IN ('tenant','subject','date_range')),
  subject_token TEXT,
  subject_label TEXT,
  layer         TEXT CHECK (layer IN ('raw','detail','summary','cache')),
  from_ms       INTEGER,
  to_ms         INTEGER,
  reason        TEXT NOT NULL,
  legal_basis   TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('active','released','expired')),
  placed_at     INTEGER NOT NULL,
  placed_by     TEXT NOT NULL,
  expires_at    INTEGER,
  released_at   INTEGER,
  released_by   TEXT
);
CREATE INDEX IF NOT EXISTS ix_holds_active
  ON legal_holds (tenant_id, status, layer);
CREATE INDEX IF NOT EXISTS ix_holds_subject
  ON legal_holds (tenant_id, subject_token, status);

-- ---------------------------------------------------------------------------
-- Business data ("the warehouse"). The subject_ref is the operational key;
-- subject_token is a deterministic HMAC used by fences and audit so that
-- evidence never carries the plaintext identifier.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS raw_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT NOT NULL,
  subject_ref   TEXT NOT NULL,
  subject_token TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  payload_json  TEXT NOT NULL DEFAULT '{}',
  occurred_at   INTEGER NOT NULL,
  ingested_at   INTEGER NOT NULL,
  source        TEXT NOT NULL DEFAULT 'collector',
  generation    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_raw_tenant_time ON raw_events (tenant_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_raw_tenant_subject ON raw_events (tenant_id, subject_token);

CREATE TABLE IF NOT EXISTS detail_records (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT NOT NULL,
  subject_ref   TEXT NOT NULL,
  subject_token TEXT NOT NULL,
  raw_event_id  INTEGER,
  category      TEXT NOT NULL,
  amount_cents  INTEGER NOT NULL DEFAULT 0,
  pii_json      TEXT NOT NULL DEFAULT '{}',
  occurred_at   INTEGER NOT NULL,
  generation    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_detail_tenant_time ON detail_records (tenant_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_detail_tenant_subject ON detail_records (tenant_id, subject_token);

CREATE TABLE IF NOT EXISTS summary_rollups (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT NOT NULL,
  subject_ref   TEXT,
  subject_token TEXT,
  category      TEXT NOT NULL,
  period_start  INTEGER NOT NULL,
  period_end    INTEGER NOT NULL,
  total_cents   INTEGER NOT NULL DEFAULT 0,
  event_count   INTEGER NOT NULL DEFAULT 0,
  computed_at   INTEGER NOT NULL,
  generation    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_summary_tenant_period ON summary_rollups (tenant_id, period_end);
CREATE INDEX IF NOT EXISTS ix_summary_tenant_subject ON summary_rollups (tenant_id, subject_token);

CREATE TABLE IF NOT EXISTS cache_entries (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id       TEXT NOT NULL,
  cache_key       TEXT NOT NULL,
  subject_ref     TEXT,
  subject_token   TEXT,
  payload_json    TEXT NOT NULL DEFAULT '{}',
  created_at      INTEGER NOT NULL,
  last_accessed_at INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  generation      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_cache_tenant_time ON cache_entries (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_cache_tenant_subject ON cache_entries (tenant_id, subject_token);

-- ---------------------------------------------------------------------------
-- Erasure fences. A fence is a durable, DB-enforced barrier:
--   * watermark: nothing at or below cutoff_ms may be inserted for the layer
--   * subject:   nothing for that subject token at or below max_generation
-- Triggers on the warehouse tables abort violating writes, so a late
-- collector cannot re-enter a range that has already been cleared even if it
-- bypasses the ingestion API.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fences (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  layer         TEXT NOT NULL,
  kind          TEXT NOT NULL CHECK (kind IN ('watermark','subject')),
  cutoff_ms     INTEGER NOT NULL DEFAULT 0,
  max_generation INTEGER NOT NULL DEFAULT 1,
  subject_token TEXT,
  request_id    TEXT,
  reason        TEXT NOT NULL DEFAULT '',
  opening_blocker INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_fence_watermark
  ON fences (tenant_id, layer) WHERE kind = 'watermark';
CREATE UNIQUE INDEX IF NOT EXISTS ux_fence_subject
  ON fences (tenant_id, layer, subject_token) WHERE kind = 'subject';

CREATE TABLE IF NOT EXISTS ingest_rejections (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT NOT NULL,
  layer         TEXT NOT NULL,
  subject_token TEXT NOT NULL,
  occurred_at   INTEGER NOT NULL,
  generation    INTEGER NOT NULL,
  reason        TEXT NOT NULL,
  fence_id      TEXT,
  attempted_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_rejections_tenant
  ON ingest_rejections (tenant_id, attempted_at);

-- ---------------------------------------------------------------------------
-- Erasure requests, immutable manifest, execution items & batches
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS erase_requests (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL REFERENCES tenants(id),
  kind          TEXT NOT NULL CHECK (kind IN ('retention_sweep','subject_erasure')),
  status        TEXT NOT NULL CHECK (status IN
                  ('awaiting_execution','running','completed',
                   'completed_with_exceptions','blocked','failed','cancelled')),
  requested_by  TEXT NOT NULL,
  requested_at  INTEGER NOT NULL,
  started_at    INTEGER,
  finished_at   INTEGER,
  cutoff_ms     INTEGER NOT NULL,
  manifest_id   TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  proof_id      TEXT,
  item_total    INTEGER NOT NULL DEFAULT 0,
  item_erased   INTEGER NOT NULL DEFAULT 0,
  item_blocked  INTEGER NOT NULL DEFAULT 0,
  item_skipped  INTEGER NOT NULL DEFAULT 0,
  error         TEXT,
  generated_by  TEXT NOT NULL DEFAULT 'console'
);
CREATE INDEX IF NOT EXISTS ix_requests_tenant
  ON erase_requests (tenant_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS ix_requests_status ON erase_requests (status);

CREATE TABLE IF NOT EXISTS erase_manifests (
  id            TEXT PRIMARY KEY,
  request_id    TEXT NOT NULL REFERENCES erase_requests(id),
  tenant_id     TEXT NOT NULL,
  payload_json  TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS erase_items (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id    TEXT NOT NULL REFERENCES erase_requests(id),
  layer         TEXT NOT NULL,
  object_ref    TEXT NOT NULL,
  occurred_at   INTEGER,
  subject_token TEXT,
  state         TEXT NOT NULL CHECK (state IN
                  ('pending','erased','blocked','skipped')),
  block_reason  TEXT,
  block_ref     TEXT,
  batch_no      INTEGER,
  erased_at     INTEGER,
  UNIQUE (request_id, layer, object_ref)
);
CREATE INDEX IF NOT EXISTS ix_items_request_layer
  ON erase_items (request_id, layer, state);

CREATE TABLE IF NOT EXISTS erase_batches (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id     TEXT NOT NULL,
  layer          TEXT NOT NULL,
  seq            INTEGER NOT NULL,
  item_count     INTEGER NOT NULL,
  commitment_root TEXT NOT NULL,
  prev_root      TEXT NOT NULL DEFAULT '',
  committed_at   INTEGER NOT NULL,
  UNIQUE (request_id, seq)
);

-- Merkle leaf per erased (or recomputed) object. Commitments are keyed HMACs
-- over canonical content: evidence proves inclusion without disclosing detail.
CREATE TABLE IF NOT EXISTS erase_proof_leaves (
  request_id   TEXT NOT NULL,
  leaf_index   INTEGER NOT NULL,
  layer        TEXT NOT NULL,
  object_ref   TEXT NOT NULL,
  commitment   TEXT NOT NULL,
  batch_no     INTEGER NOT NULL,
  PRIMARY KEY (request_id, leaf_index)
);

CREATE TABLE IF NOT EXISTS erase_proofs (
  id             TEXT PRIMARY KEY,
  request_id     TEXT NOT NULL,
  version        INTEGER NOT NULL DEFAULT 1,
  payload_json   TEXT NOT NULL,
  proof_hash     TEXT NOT NULL,
  merkle_root    TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('unverified','verified','failed')),
  verified_at    INTEGER,
  verification_json TEXT,
  created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_proofs_request ON erase_proofs (request_id);

-- ---------------------------------------------------------------------------
-- Append-only tenant audit chain
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_events (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id    TEXT NOT NULL,
  request_id   TEXT,
  type         TEXT NOT NULL,
  at           INTEGER NOT NULL,
  actor        TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  prev_hash    TEXT NOT NULL,
  hash         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_tenant ON audit_events (tenant_id, seq);

-- ---------------------------------------------------------------------------
-- Subject consent / generation control. Erasing a subject records a tombstone
-- fence; data may only return after an explicit consent renewal that raises
-- the generation above the erased generation.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS subject_consents (
  tenant_id      TEXT NOT NULL,
  subject_token  TEXT NOT NULL,
  generation     INTEGER NOT NULL,
  consent_ref    TEXT NOT NULL,
  updated_at     INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, subject_token)
);
