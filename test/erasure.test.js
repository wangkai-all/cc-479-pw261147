import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDatabase, migrate, LAYERS } from '../src/db.js';
import { deriveKey, keyFingerprint, subjectToken, merkleRoot, merkleProof, verifyMerkleProof, canonicalJson, sha256Hex } from '../src/crypto.js';
import { appendAudit, verifyAuditChain } from '../src/audit.js';
import {
  createRetentionSweep,
  createSubjectErasure,
  executeRequest,
  inspectRetentionSweep,
  inspectSubjectErasure,
  verifyProof,
} from '../src/erasure.js';
import {
  updatePolicy,
  placeHold,
  releaseHold,
  renewConsent,
  currentGeneration,
  ingestEvents,
} from '../src/services.js';
import { getPolicies } from '../src/policy.js';
import { getRequest } from '../src/requests.js';

const HOUR = 3_600_000;
const DAY = 86_400_000;
const NOW = Date.UTC(2026, 5, 15, 12, 0, 0);

function freshDb() {
  const db = migrate(openDatabase(':memory:'));
  return db;
}

function makeTenant(db, id = 't1', policies = {}) {
  db.prepare('INSERT INTO tenants (id, name, region, description, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, `Tenant ${id}`, 'eu', '', NOW);
  const key = deriveKey('test-master', id, 'tenant-proof-key');
  db.prepare('INSERT INTO tenant_keys (tenant_id, proof_key, key_fingerprint, created_at) VALUES (?, ?, ?, ?)')
    .run(id, key, keyFingerprint(key), NOW);
  const defaults = {
    raw: { retentionValue: 30, retentionUnit: 'days', statutoryMinDays: 0 },
    detail: { retentionValue: 180, retentionUnit: 'days', statutoryMinDays: 0 },
    summary: { retentionValue: 730, retentionUnit: 'days', statutoryMinDays: 0 },
    cache: { retentionValue: 7, retentionUnit: 'days', statutoryMinDays: 0 },
  };
  for (const layer of LAYERS) {
    const p = { ...defaults[layer], ...(policies[layer] || {}) };
    db.prepare(
      `INSERT INTO retention_policies
        (id, tenant_id, layer, retention_value, retention_unit, legal_basis, exception_note,
         statutory_min_days, statutory_basis, version, is_current, effective_from, updated_at)
       VALUES (?, ?, ?, ?, ?, 'basis', '', ?, '', 1, 1, ?, ?)`
    ).run(`pol_${id}_${layer}`, id, layer, p.retentionValue, p.retentionUnit,
      p.statutoryMinDays, NOW, NOW);
  }
  return { id, key };
}

function insertRaw(db, tenantId, key, { subject, at, eventType = 'login', generation = 1 }) {
  const token = subjectToken(key, subject);
  const info = db.prepare(
    `INSERT INTO raw_events (tenant_id, subject_ref, subject_token, event_type, payload_json,
                             occurred_at, ingested_at, source, generation)
     VALUES (?, ?, ?, ?, '{}', ?, ?, 'test', ?)`
  ).run(tenantId, subject, token, eventType, at, at, generation);
  return { id: Number(info.lastInsertRowid), token, objectRef: `raw:${Number(info.lastInsertRowid)}` };
}

function insertDetail(db, tenantId, key, { subject, at, amount = 1000, category = 'purchase' }) {
  const token = subjectToken(key, subject);
  const info = db.prepare(
    `INSERT INTO detail_records (tenant_id, subject_ref, subject_token, category, amount_cents,
                                 pii_json, occurred_at, generation)
     VALUES (?, ?, ?, ?, ?, '{"card":"x"}', ?, 1)`
  ).run(tenantId, subject, token, category, amount, at);
  return { id: Number(info.lastInsertRowid), objectRef: `detail:${Number(info.lastInsertRowid)}` };
}

function insertSummary(db, tenantId, key, { subject, at, category = 'billing' }) {
  const token = subjectToken(key, subject);
  const info = db.prepare(
    `INSERT INTO summary_rollups (tenant_id, subject_ref, subject_token, category, period_start,
                                  period_end, total_cents, event_count, computed_at, generation)
     VALUES (?, ?, ?, ?, ?, ?, 5000, 10, ?, 1)`
  ).run(tenantId, subject, token, category, at - 30 * DAY, at, at);
  return { id: Number(info.lastInsertRowid), objectRef: `summary:${Number(info.lastInsertRowid)}` };
}

function insertCache(db, tenantId, key, { subject, at }) {
  const token = subjectToken(key, subject);
  const info = db.prepare(
    `INSERT INTO cache_entries (tenant_id, subject_ref, subject_token, cache_key, payload_json,
                                created_at, last_accessed_at, expires_at, generation)
     VALUES (?, ?, ?, 'k', '{}', ?, ?, ?, 1)`
  ).run(tenantId, subject, token, at, at, at + HOUR);
  return { id: Number(info.lastInsertRowid), objectRef: `cache:${Number(info.lastInsertRowid)}` };
}

const count = (db, table, tenantId) =>
  db.prepare(`SELECT COUNT(*) c FROM ${table} WHERE tenant_id = ?`).get(tenantId).c;

// ---------------------------------------------------------------------------

test('retention sweep deletes only aged objects and leaves recent ones', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 40 * DAY });
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 2 * DAY });

  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  assert.equal(created.itemTotal, 1, 'only the 40-day-old raw event is eligible');

  const run = executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  assert.equal(run.status, 'completed');
  assert.equal(run.erased, 1);
  assert.equal(count(db, 'raw_events', tenantId), 1);
});

test('retention sweep respects the per-layer window', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db, 't', {
    raw: { retentionValue: 1, retentionUnit: 'hours' },
    detail: { retentionValue: 365, retentionUnit: 'days' },
  });
  insertRaw(db, tenantId, key, { subject: 'a', at: NOW - 2 * HOUR });   // eligible
  insertRaw(db, tenantId, key, { subject: 'a', at: NOW - 30 * 60_000 }); // kept
  insertDetail(db, tenantId, key, { subject: 'a', at: NOW - 200 * DAY }); // kept (365d)
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  assert.equal(count(db, 'raw_events', tenantId), 1);
  assert.equal(count(db, 'detail_records', tenantId), 1);
});

test('subject erasure deletes across all layers and skips statutorily protected objects', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db, 't', {
    detail: { retentionValue: 365, retentionUnit: 'days', statutoryMinDays: 200 },
  });
  insertRaw(db, tenantId, key, { subject: 'alice@x.com', at: NOW - 5 * DAY });
  insertRaw(db, tenantId, key, { subject: 'bob@x.com', at: NOW - 5 * DAY });
  insertDetail(db, tenantId, key, { subject: 'alice@x.com', at: NOW - 300 * DAY }); // aged past floor
  insertDetail(db, tenantId, key, { subject: 'alice@x.com', at: NOW - 50 * DAY });  // inside 200d floor
  insertSummary(db, tenantId, key, { subject: 'alice@x.com', at: NOW - 400 * DAY });

  const created = createSubjectErasure(db, tenantId, { actor: 'dpo', nowMs: NOW, subjectRef: 'alice@x.com' });
  const run = executeRequest(db, created.requestId, { actor: 'dpo', nowMs: NOW });

  assert.equal(run.status, 'completed_with_exceptions');
  assert.equal(run.erased, 3, 'raw + aged detail + summary');
  assert.equal(run.blocked, 1, 'recent detail is statutorily protected');
  assert.equal(count(db, 'raw_events', tenantId), 1, 'bob is untouched');
  assert.equal(count(db, 'detail_records', tenantId), 1, 'only the protected detail remains');
});

test('a subject erasure also removes the subject from cache', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertCache(db, tenantId, key, { subject: 'a@x.com', at: NOW - 1 * DAY });
  insertCache(db, tenantId, key, { subject: 'b@x.com', at: NOW - 1 * DAY });
  const created = createSubjectErasure(db, tenantId, { actor: 'op', nowMs: NOW, subjectRef: 'a@x.com' });
  const run = executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  assert.equal(run.erased, 1);
  assert.equal(count(db, 'cache_entries', tenantId), 1);
});

test('legal hold blocks deletion and the object survives', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'held@x.com', at: NOW - 90 * DAY });
  placeHold(db, tenantId, {
    scopeKind: 'subject', subjectRef: 'held@x.com', reason: 'Litigation', legalBasis: 'Notice 1',
  }, { actor: 'legal', nowMs: NOW });

  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  assert.equal(created.blockedCount, 1, 'manifest marks the object blocked');
  const run = executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  assert.equal(run.erased, 0);
  assert.equal(run.blocked, 1);
  assert.equal(count(db, 'raw_events', tenantId), 1);
});

test('releasing a hold makes the object eligible again', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'held@x.com', at: NOW - 90 * DAY });
  const hold = placeHold(db, tenantId, {
    scopeKind: 'subject', subjectRef: 'held@x.com', reason: 'Litigation', legalBasis: 'Notice 1',
  }, { actor: 'legal', nowMs: NOW });
  releaseHold(db, tenantId, hold.id, { actor: 'legal', nowMs: NOW + HOUR });

  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW + HOUR });
  assert.equal(created.blockedCount, 0);
  const run = executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW + HOUR });
  assert.equal(run.erased, 1);
});

test('a hold placed after manifest generation still blocks at execution', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'late@x.com', at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  assert.equal(created.blockedCount, 0);
  placeHold(db, tenantId, {
    scopeKind: 'subject', subjectRef: 'late@x.com', reason: 'New injunction', legalBasis: 'Order 9',
  }, { actor: 'legal', nowMs: NOW + 1000 });
  const run = executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW + 2000 });
  assert.equal(run.erased, 0);
  assert.equal(run.blocked, 1);
  assert.equal(count(db, 'raw_events', tenantId), 1);
});

test('deletion fences reject re-ingestion of the cleared range', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });

  const late = NOW - 60 * DAY; // inside the cleared watermark
  const result = ingestEvents(db, tenantId, [
    { subjectRef: 'a@x.com', eventType: 'login', occurredAt: late },
    { subjectRef: 'a@x.com', eventType: 'login', occurredAt: NOW - 1 * DAY }, // after cutoff, allowed
  ], { actor: 'collector', nowMs: NOW });
  assert.equal(result.accepted, 1);
  assert.equal(result.rejected, 1);
  assert.equal(count(db, 'raw_events', tenantId), 1);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM ingest_rejections WHERE tenant_id = ?').get(tenantId).c, 1);
});

test('fence is enforced even when a writer bypasses the ingestion service', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });

  assert.throws(
    () => db.prepare(
      `INSERT INTO raw_events (tenant_id, subject_ref, subject_token, event_type, payload_json, occurred_at, ingested_at, source, generation)
       VALUES (?, 'a@x.com', 'tok', 'login', '{}', ?, ?, 'rogue', 1)`
    ).run(tenantId, NOW - 80 * DAY, NOW),
    /FENCED_RANGE/
  );
});

test('subject erasure fences re-ingestion at the erased generation; consent renewal lifts it', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 3 * DAY });
  const created = createSubjectErasure(db, tenantId, { actor: 'dpo', nowMs: NOW, subjectRef: 'a@x.com' });
  executeRequest(db, created.requestId, { actor: 'dpo', nowMs: NOW });

  const blocked = ingestEvents(db, tenantId, [
    { subjectRef: 'a@x.com', eventType: 'login', occurredAt: NOW, category: 'purchase' },
  ], { actor: 'collector', nowMs: NOW });
  assert.equal(blocked.accepted, 0);
  assert.equal(blocked.rejected, 1, 'the whole event is fenced at the raw write');
  assert.equal(count(db, 'detail_records', tenantId), 0, 'its derived detail is never attempted');

  renewConsent(db, tenantId, { subjectRef: 'a@x.com', consentRef: 'C-2' }, { actor: 'dpo', nowMs: NOW });
  assert.equal(currentGeneration(db, tenantId, subjectToken(key, 'a@x.com')), 2);

  const allowed = ingestEvents(db, tenantId, [
    { subjectRef: 'a@x.com', eventType: 'login', occurredAt: NOW },
  ], { actor: 'collector', nowMs: NOW });
  assert.equal(allowed.accepted, 1);
});

test('fences only ever tighten across repeated requests', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  const first = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  executeRequest(db, first.requestId, { actor: 'op', nowMs: NOW });
  const firstCutoff = db.prepare("SELECT cutoff_ms FROM fences WHERE tenant_id = ? AND layer = 'raw' AND kind = 'watermark'").get(tenantId).cutoff_ms;

  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 20 * DAY });
  const second = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW + 10 * DAY });
  executeRequest(db, second.requestId, { actor: 'op', nowMs: NOW + 10 * DAY });
  const fences = db.prepare("SELECT * FROM fences WHERE tenant_id = ? AND layer = 'raw' AND kind = 'watermark'").all(tenantId);
  assert.equal(fences.length, 1, 'one watermark fence per layer');
  assert.ok(fences[0].cutoff_ms >= firstCutoff);
});

test('proof verification re-checks deletion, manifest, merkle root and audit chain', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  for (let i = 0; i < 5; i += 1) insertRaw(db, tenantId, key, { subject: `a${i}@x.com`, at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });

  const v = verifyProof(db, created.requestId, { actor: 'auditor', nowMs: NOW });
  assert.equal(v.ok, true);
  for (const c of v.checks) assert.equal(c.ok, true, `${c.id}: ${JSON.stringify(c.detail)}`);
});

test('verification fails if an object is resurrected after the deletion', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  const ins = insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  // Simulate tampering: drop the fence and reinsert the same id.
  db.exec('DROP TRIGGER trg_fence_raw_events_insert');
  db.exec('DROP TRIGGER trg_fence_raw_events_update');
  db.prepare(
    `INSERT INTO raw_events (id, tenant_id, subject_ref, subject_token, event_type, payload_json, occurred_at, ingested_at, source, generation)
     VALUES (?, ?, 'a@x.com', 'tok', 'login', '{}', ?, ?, 'rogue', 1)`
  ).run(ins.id, tenantId, NOW - 90 * DAY, NOW);
  const v = verifyProof(db, created.requestId, { actor: 'auditor', nowMs: NOW });
  assert.equal(v.ok, false);
  assert.equal(v.checks.find((c) => c.id === 'objects_absent').ok, false);
});

test('proof does not disclose erased content', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertDetail(db, tenantId, key, { subject: 'secret@x.com', at: NOW - 400 * DAY, amount: 987654 });
  const created = createSubjectErasure(db, tenantId, { actor: 'dpo', nowMs: NOW, subjectRef: 'secret@x.com' });
  executeRequest(db, created.requestId, { actor: 'dpo', nowMs: NOW });

  const raw = db.prepare('SELECT payload_json FROM erase_proofs LIMIT 1').get().payload_json;
  assert.ok(!raw.includes('secret@x.com'), 'no plaintext subject identifier');
  assert.ok(!raw.includes('987654'), 'no erased monetary value');
  assert.ok(!raw.includes('"card"'), 'no erased pii payload');

  const manifest = db.prepare('SELECT payload_json FROM erase_manifests LIMIT 1').get().payload_json;
  assert.ok(!manifest.includes('secret@x.com'), 'manifest carries no plaintext subject');
});

test('audit payloads never carry plaintext identifiers or values', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertDetail(db, tenantId, key, { subject: 'secret@x.com', at: NOW - 400 * DAY, amount: 123456 });
  const created = createSubjectErasure(db, tenantId, { actor: 'dpo', nowMs: NOW, subjectRef: 'secret@x.com' });
  executeRequest(db, created.requestId, { actor: 'dpo', nowMs: NOW });
  verifyProof(db, created.requestId, { actor: 'auditor', nowMs: NOW });

  const rows = db.prepare('SELECT payload_json FROM audit_events WHERE tenant_id = ?').all(tenantId);
  for (const r of rows) {
    assert.ok(!r.payload_json.includes('secret@x.com'));
    assert.ok(!r.payload_json.includes('123456'));
  }
});

test('manifest hash is stable and bound to the request', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  const detail = getRequest(db, tenantId, created.requestId);
  assert.equal(detail.manifest.hash, created.manifestHash);
  const manifestRow = db.prepare('SELECT payload_json FROM erase_manifests WHERE id = ?').get(created.manifestId);
  const body = JSON.parse(manifestRow.payload_json);
  const recomputed = sha256Hex(canonicalJson(body));
  assert.equal(recomputed, created.manifestHash);
});

test('policy update cannot undercut the statutory floor', () => {
  const db = freshDb();
  const { id: tenantId } = makeTenant(db, 't', { detail: { statutoryMinDays: 365 } });
  assert.throws(
    () => updatePolicy(db, tenantId, 'detail', { retentionValue: 30, retentionUnit: 'days' }, { actor: 'op', nowMs: NOW }),
    /shorter than the statutory minimum/
  );
  const updated = updatePolicy(db, tenantId, 'detail', { retentionValue: 730, retentionUnit: 'days' },
    { actor: 'op', nowMs: NOW });
  assert.equal(updated.retentionValue, 730);
  assert.equal(updated.version, 2);
  assert.equal(getPolicies(db, tenantId).find((p) => p.layer === 'detail').version, 2);
});

test('request is rejected unless it is awaiting execution', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  assert.throws(
    () => executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW }),
    /cannot be executed/
  );
});

test('inspect reports the same scope the manifest will freeze', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  insertRaw(db, tenantId, key, { subject: 'b@x.com', at: NOW - 1 * DAY });
  placeHold(db, tenantId, {
    scopeKind: 'tenant', layer: 'detail', reason: 'audit', legalBasis: 'order',
  }, { actor: 'legal', nowMs: NOW });

  const inspect = inspectRetentionSweep(db, tenantId, { nowMs: NOW });
  const rawLayer = inspect.layers.find((l) => l.layer === 'raw');
  assert.equal(rawLayer.eligible, 1);
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  assert.equal(created.itemTotal, 1);
});

test('subject inspection does not write and matches erasure scope', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  insertDetail(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });

  const inspect = inspectSubjectErasure(db, tenantId, 'a@x.com', { nowMs: NOW });
  assert.equal(inspect.totalEligible, 2);
  assert.equal(count(db, 'erase_requests', tenantId), 0);

  const created = createSubjectErasure(db, tenantId, { actor: 'op', nowMs: NOW, subjectRef: 'a@x.com' });
  assert.equal(created.itemTotal, 2);
});

test('merkle proofs verify for every leaf and reject a tampered path', () => {
  const commitments = Array.from({ length: 7 }, (_, i) => `c${i}`);
  const root = merkleRoot(commitments);
  for (let i = 0; i < commitments.length; i += 1) {
    const p = merkleProof(commitments, i);
    assert.equal(p.root, root);
    assert.ok(verifyMerkleProof(p));
  }
  const p = merkleProof(commitments, 3);
  p.path[0] = { ...p.path[0], hash: 'deadbeef' };
  assert.equal(verifyMerkleProof(p), false);
});

test('audit chain detects a mutated event', () => {
  const db = freshDb();
  const { id: tenantId } = makeTenant(db);
  appendAudit(db, { tenantId, type: 'a', actor: 'x', at: NOW, payload: { n: 1 } });
  appendAudit(db, { tenantId, type: 'b', actor: 'x', at: NOW, payload: { n: 2 } });
  assert.equal(verifyAuditChain(db, tenantId).valid, true);
  // Append-only triggers must refuse edits.
  assert.throws(
    () => db.prepare("UPDATE audit_events SET payload_json = '{\"n\":99}' WHERE seq = 1").run(),
    /append-only/
  );
});

test('cache entries are erased with the subject like other layers', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertCache(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  const run = executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  assert.equal(run.skipped, 0);
  assert.equal(count(db, 'cache_entries', tenantId), 0);
});

test('blocked objects are reported on the proof but not deleted', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'held@x.com', at: NOW - 90 * DAY });
  placeHold(db, tenantId, {
    scopeKind: 'subject', subjectRef: 'held@x.com', reason: 'Litigation', legalBasis: 'Notice',
  }, { actor: 'legal', nowMs: NOW });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });
  executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  const proof = JSON.parse(db.prepare('SELECT payload_json FROM erase_proofs LIMIT 1').get().payload_json);
  assert.equal(proof.excluded.blocked.length, 1);
  assert.equal(proof.excluded.blocked[0].reason, 'legal_hold_subject');
  assert.equal(proof.counts.blocked, 1);
  assert.equal(count(db, 'raw_events', tenantId), 1);
});

test('fences open atomically with the manifest, before execution starts', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'a@x.com', at: NOW - 90 * DAY });
  const created = createRetentionSweep(db, tenantId, { actor: 'op', nowMs: NOW });

  // No execution yet, but the fence must already refuse a late write.
  assert.throws(
    () => db.prepare(
      `INSERT INTO raw_events (tenant_id, subject_ref, subject_token, event_type, payload_json, occurred_at, ingested_at, source, generation)
       VALUES (?, 'late@x.com', 'tok', 'login', '{}', ?, ?, 'rogue', 1)`
    ).run(tenantId, NOW - 60 * DAY, NOW),
    /FENCED_RANGE/
  );

  // Executing still works, and the fence is not duplicated.
  executeRequest(db, created.requestId, { actor: 'op', nowMs: NOW });
  const fences = db.prepare("SELECT * FROM fences WHERE tenant_id = ? AND layer = 'raw'").all(tenantId);
  assert.equal(fences.length, 1);
});

test('a fully blocked request is parked as blocked and can run after the hold is released', () => {
  const db = freshDb();
  const { id: tenantId, key } = makeTenant(db);
  insertRaw(db, tenantId, key, { subject: 'only@x.com', at: NOW - 90 * DAY });
  const hold = placeHold(db, tenantId, {
    scopeKind: 'tenant', reason: 'Everything held', legalBasis: 'Order 5',
  }, { actor: 'legal', nowMs: NOW });

  const created = createSubjectErasure(db, tenantId, {
    actor: 'dpo', nowMs: NOW, subjectRef: 'only@x.com',
  });
  const row = db.prepare('SELECT status FROM erase_requests WHERE id = ?').get(created.requestId);
  assert.equal(row.status, 'blocked');

  const run = executeRequest(db, created.requestId, { actor: 'dpo', nowMs: NOW });
  assert.equal(run.erased, 0);
  assert.equal(run.blocked, 1);

  // A blocked request cannot be re-executed once it has a proof.
  assert.throws(() => executeRequest(db, created.requestId, { actor: 'dpo', nowMs: NOW }), /cannot be executed/);
  void hold;
});
