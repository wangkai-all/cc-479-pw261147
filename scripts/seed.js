import { config, clock } from '../src/config.js';
import { openDatabase, migrate, tx, uuid } from '../src/db.js';
import { deriveKey, keyFingerprint, subjectToken } from '../src/crypto.js';
import { appendAudit } from '../src/audit.js';
import fs from 'node:fs';
import path from 'node:path';

const HOUR = 3_600_000;
const DAY = 86_400_000;

const TENANTS = [
  {
    id: 'northwind',
    name: 'Northwind Health',
    region: 'eu-central-1',
    description: 'EU healthcare analytics; strict statutory floor on clinical detail records.',
    policies: {
      raw: { retentionValue: 30, retentionUnit: 'days', legalBasis: 'Telemetry minimisation (GDPR Art. 5(1)(e))', statutoryMinDays: 0, statutoryBasis: '' },
      detail: { retentionValue: 400, retentionUnit: 'days', legalBasis: 'Clinical record retention', statutoryMinDays: 365, statutoryBasis: 'EU member-state healthcare record minimum (365 days)' },
      summary: { retentionValue: 730, retentionUnit: 'days', legalBasis: 'Aggregate analytics', statutoryMinDays: 0, statutoryBasis: '' },
      cache: { retentionValue: 3, retentionUnit: 'hours', legalBasis: 'Derived cache, rebuildable', statutoryMinDays: 0, statutoryBasis: '' },
    },
  },
  {
    id: 'lumenpay',
    name: 'Lumen Pay',
    region: 'us-east-1',
    description: 'Payments processor; transaction detail carries a 7-year financial record floor.',
    policies: {
      raw: { retentionValue: 45, retentionUnit: 'days', legalBasis: 'Fraud telemetry window', statutoryMinDays: 0, statutoryBasis: '' },
      detail: { retentionValue: 2555, retentionUnit: 'days', legalBasis: 'Financial record keeping', statutoryMinDays: 2555, statutoryBasis: '7-year financial records rule' },
      summary: { retentionValue: 1095, retentionUnit: 'days', legalBasis: 'Aggregate reporting', statutoryMinDays: 0, statutoryBasis: '' },
      cache: { retentionValue: 1, retentionUnit: 'hours', legalBasis: 'Derived cache, rebuildable', statutoryMinDays: 0, statutoryBasis: '' },
    },
  },
  {
    id: 'atlas',
    name: 'Atlas Logistics',
    region: 'ap-southeast-2',
    description: 'Low-retention demo tenant: short windows, no statutory floor.',
    policies: {
      raw: { retentionValue: 12, retentionUnit: 'hours', legalBasis: 'Short-lived operational telemetry', statutoryMinDays: 0, statutoryBasis: '' },
      detail: { retentionValue: 14, retentionUnit: 'days', legalBasis: 'Delivery record retention', statutoryMinDays: 0, statutoryBasis: '' },
      summary: { retentionValue: 90, retentionUnit: 'days', legalBasis: 'Aggregate analytics', statutoryMinDays: 0, statutoryBasis: '' },
      cache: { retentionValue: 2, retentionUnit: 'hours', legalBasis: 'Derived cache, rebuildable', statutoryMinDays: 0, statutoryBasis: '' },
    },
  },
];

const JSON_PAYLOAD = {
  raw: '{"route":"/v2/dispatch","lat":51.5,"status":"ok"}',
  detail: '{"invoice":"INV-4821","channel":"card"}',
  cache: '{"ttl":900,"view":"balance"}',
  summary: '{}',
};

function ensureTenant(db, def, nowMs) {
  const existing = db.prepare('SELECT id FROM tenants WHERE id = ?').get(def.id);
  if (!existing) {
    db.prepare('INSERT INTO tenants (id, name, region, description, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(def.id, def.name, def.region, def.description, nowMs);
  }
  if (!db.prepare('SELECT tenant_id FROM tenant_keys WHERE tenant_id = ?').get(def.id)) {
    const key = deriveKey(config.masterSecret, def.id, 'tenant-proof-key');
    db.prepare('INSERT INTO tenant_keys (tenant_id, proof_key, key_fingerprint, created_at) VALUES (?, ?, ?, ?)')
      .run(def.id, key, keyFingerprint(key), nowMs);
  }
  for (const [layer, p] of Object.entries(def.policies)) {
    const has = db.prepare('SELECT id FROM retention_policies WHERE tenant_id = ? AND layer = ? AND is_current = 1')
      .get(def.id, layer);
    if (has) continue;
    db.prepare(
      `INSERT INTO retention_policies
        (id, tenant_id, layer, retention_value, retention_unit, legal_basis, exception_note,
         statutory_min_days, statutory_basis, version, is_current, effective_from, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, 1, 1, ?, ?)`
    ).run(uuid('pol'), def.id, layer, p.retentionValue, p.retentionUnit, p.legalBasis,
      p.statutoryMinDays, p.statutoryBasis, nowMs, nowMs);
  }
}

const SUBJECTS = [
  { ref: 'alice@example.com', label: 'Alice' },
  { ref: 'bob@example.com', label: 'Bob' },
  { ref: 'carol@example.com', label: 'Carol' },
  { ref: 'dan@example.com', label: 'Dan' },
];

function seedData(db, def, nowMs) {
  const key = db.prepare('SELECT proof_key FROM tenant_keys WHERE tenant_id = ?').get(def.id).proof_key;
  const policies = Object.fromEntries(
    db.prepare('SELECT * FROM retention_policies WHERE tenant_id = ? AND is_current = 1').all(def.id)
      .map((p) => [p.layer, p])
  );
  const retentionMs = (layer) => policies[layer].retention_value *
    (policies[layer].retention_unit === 'hours' ? HOUR : DAY);
  const cutoff = (layer) => nowMs - retentionMs(layer);

  const insRaw = db.prepare(
    `INSERT INTO raw_events (tenant_id, subject_ref, subject_token, event_type, payload_json, occurred_at, ingested_at, source, generation)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`
  );
  const insDetail = db.prepare(
    `INSERT INTO detail_records (tenant_id, subject_ref, subject_token, category, amount_cents, pii_json, occurred_at, generation)
     VALUES (?, ?, ?, ?, ?, ?, ?, 1)`
  );
  const insSummary = db.prepare(
    `INSERT INTO summary_rollups (tenant_id, subject_ref, subject_token, category, period_start, period_end, total_cents, event_count, computed_at, generation)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`
  );
  const insCache = db.prepare(
    `INSERT INTO cache_entries (tenant_id, subject_ref, subject_token, cache_key, payload_json, created_at, last_accessed_at, expires_at, generation)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`
  );

  // Deterministic lattice: ages expressed as a fraction of each layer's
  // retention window, so every tenant's short or long window straddles the
  // cutoff in the same way (roughly half the objects pending, half retained).
  const spreads = {
    raw: [0.4, 0.75, 0.95, 1.05, 1.3, 2.2, 4],
    detail: [0.35, 0.8, 0.98, 1.02, 1.4, 2.5],
    summary: [0.3, 0.6, 0.9, 1.1, 2],
    cache: [0.2, 0.85, 0.98, 1.1, 3],
  };

  for (const [oi, subject] of SUBJECTS.entries()) {
    const token = subjectToken(key, subject.ref);
    for (const layer of ['raw', 'detail', 'summary', 'cache']) {
      const window = retentionMs(layer);
      const ages = spreads[layer].map((mult) => Math.round(window * (mult + oi * 0.08)));
      for (const [i, ageMs] of ages.entries()) {
        const t = nowMs - ageMs;
        if (layer === 'raw') {
          insRaw.run(def.id, subject.ref, token, ['page_view', 'checkout', 'login', 'export'][i % 4],
            JSON_PAYLOAD.raw, t, t + HOUR, 'collector');
        } else if (layer === 'detail') {
          insDetail.run(def.id, subject.ref, token, ['subscription', 'refund', 'purchase'][i % 3],
            1200 + oi * 510 + i * 75, JSON_PAYLOAD.detail, t);
        } else if (layer === 'summary') {
          insSummary.run(def.id, subject.ref, token, 'billing', t, t + 30 * DAY, 90000 + oi * 1000, 12 + i, t + 60_000);
        } else {
          insCache.run(def.id, subject.ref, token, `acct:${subject.ref}:${i}`, JSON_PAYLOAD.cache, t, t + 60_000, t + 900_000);
        }
      }
    }
  }
}

function seedHolds(db, def, nowMs) {
  const existing = db.prepare('SELECT COUNT(*) c FROM legal_holds WHERE tenant_id = ?').get(def.id).c;
  if (existing > 0) return;
  const key = db.prepare('SELECT proof_key FROM tenant_keys WHERE tenant_id = ?').get(def.id).proof_key;
  const holdSubject = def.id === 'northwind' ? 'carol@example.com' : 'bob@example.com';
  const token = subjectToken(key, holdSubject);
  const id = uuid('hold');
  db.prepare(
    `INSERT INTO legal_holds
      (id, tenant_id, scope_kind, subject_token, subject_label, layer, from_ms, to_ms,
       reason, legal_basis, status, placed_at, placed_by, expires_at)
     VALUES (?, ?, 'subject', ?, ?, NULL, NULL, NULL, ?, ?, 'active', ?, ?, ?)`
  ).run(
    id, def.id, token, def.id === 'northwind' ? 'Carol (litigation)' : 'Bob (regulatory inquiry)',
    'Pending litigation hold', 'Litigation hold notice 2026-118',
    nowMs - 20 * DAY, 'compliance@ops', nowMs + 180 * DAY
  );

  const tenantHold = uuid('hold');
  db.prepare(
    `INSERT INTO legal_holds
      (id, tenant_id, scope_kind, subject_token, subject_label, layer, from_ms, to_ms,
       reason, legal_basis, status, placed_at, placed_by, expires_at)
     VALUES (?, ?, 'tenant', NULL, NULL, ?, NULL, NULL, ?, ?, 'active', ?, ?, NULL)`
  ).run(
    tenantHold, def.id, 'summary',
    'Quarterly aggregate freeze awaiting audit sign-off',
    'External audit instruction', nowMs - 4 * DAY, 'audit@ops'
  );
}

export function seed(db, { nowMs = clock.now(), reset = false } = {}) {
  if (reset) {
    const tables = [
      'erase_proof_leaves', 'erase_proofs', 'erase_batches', 'erase_items', 'erase_manifests',
      'erase_requests', 'audit_events', 'ingest_rejections', 'fences', 'legal_holds',
      'retention_policies', 'subject_consents', 'cache_entries', 'summary_rollups',
      'detail_records', 'raw_events', 'tenant_keys', 'tenants',
    ];
    db.exec('PRAGMA foreign_keys = OFF');
    for (const t of tables) db.exec(`DELETE FROM ${t}`);
    db.exec(`DELETE FROM sqlite_sequence WHERE name IN ('raw_events','detail_records','summary_rollups','cache_entries','erase_items','erase_batches','erase_proof_leaves','audit_events','ingest_rejections')`);
    db.exec('PRAGMA foreign_keys = ON');
  }
  let seeded = 0;
  tx(db, () => {
    for (const def of TENANTS) {
      const fresh = !db.prepare('SELECT id FROM tenants WHERE id = ?').get(def.id);
      ensureTenant(db, def, nowMs);
      if (fresh) {
        seedData(db, def, nowMs);
        seedHolds(db, def, nowMs);
        const key = db.prepare('SELECT proof_key FROM tenant_keys WHERE tenant_id = ?').get(def.id).proof_key;
        appendAudit(db, {
          tenantId: def.id,
          type: 'tenant.seeded',
          actor: 'system',
          at: nowMs,
          payload: { tenant: def.id, keyFingerprint: keyFingerprint(key) },
        });
        seeded += 1;
      }
    }
  });
  return { seeded, nowMs };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const reset = process.argv.includes('--reset');
  const dbPath = config.dbPath;
  if (reset && dbPath !== ':memory:' && fs.existsSync(dbPath)) {
    // Recreate in place rather than deleting the file so WAL sidecars are not
    // left pointing at a removed inode.
    const db = migrate(openDatabase(dbPath));
    const result = seed(db, { reset: true });
    console.log(`reset database at ${dbPath}; seeded ${result.seeded} tenants`);
    db.close();
  } else {
    const db = migrate(openDatabase(dbPath));
    const result = seed(db, { reset });
    console.log(`seeded ${result.seeded} new tenant(s) at ${dbPath}`);
    for (const t of TENANTS) {
      const counts = db.prepare(
        `SELECT (SELECT COUNT(*) FROM raw_events WHERE tenant_id=?) raw,
                (SELECT COUNT(*) FROM detail_records WHERE tenant_id=?) detail,
                (SELECT COUNT(*) FROM summary_rollups WHERE tenant_id=?) summary,
                (SELECT COUNT(*) FROM cache_entries WHERE tenant_id=?) cache`
      ).get(t.id, t.id, t.id, t.id);
      console.log(`  ${t.id}: raw=${counts.raw} detail=${counts.detail} summary=${counts.summary} cache=${counts.cache}`);
    }
    db.close();
  }
}
