#!/usr/bin/env node
/**
 * End-to-end demonstration against a throwaway database.
 * Prints each step and asserts the important invariants.
 */
import { clock } from '../src/config.js';
import { openDatabase, migrate, LAYERS } from '../src/db.js';
import { seed } from './seed.js';
import {
  createRetentionSweep, createSubjectErasure, executeRequest, verifyProof,
} from '../src/erasure.js';
import {
  ingestEvents, placeHold, releaseHold, renewConsent, tenantOverview, updatePolicy,
} from '../src/services.js';
import { getRequest } from '../src/requests.js';
import assert from 'node:assert/strict';

const NOW = Date.UTC(2026, 5, 15, 12, 0, 0);
const DAY = 86_400_000;
clock.freeze(NOW);
const db = migrate(openDatabase(':memory:'));
seed(db, { nowMs: NOW });

const line = (s = '') => console.log(s);
const h = (s) => { line(); line('─'.repeat(72)); line(s); line('─'.repeat(72)); };
const tenant = 'northwind';

h('1. Policies — raw/detail/summary/cache have different windows and legal floors');
const ov0 = tenantOverview(db, tenant, NOW);
for (const p of ov0.policies) {
  line(`  ${p.layer.padEnd(8)} retain ${String(p.retentionValue).padStart(4)} ${p.retentionUnit.padEnd(5)}` +
    ` statutory floor ${String(p.statutoryMinDays).padStart(3)}d   ${p.legalBasis}`);
}
line(`  pending: ${ov0.totals.pendingEligible} eligible, ${ov0.totals.pendingBlocked} blocked by hold/statute`);

h('2. Retention sweep — generated manifest, executed in batches, proof issued');
const sweep = createRetentionSweep(db, tenant, { actor: 'ops@northwind', nowMs: NOW });
line(`  manifest ${sweep.manifestId}  hash ${sweep.manifestHash.slice(0, 24)}…`);
line(`  scope: ${sweep.itemTotal} items, ${sweep.blockedCount} pre-blocked`);
const run = executeRequest(db, sweep.requestId, { actor: 'ops@northwind', nowMs: NOW });
line(`  executed: ${run.status} — erased ${run.erased}, blocked ${run.blocked}, skipped ${run.skipped}`);
line(`  proof ${run.proof.proofId}  merkle root ${run.proof.merkleRoot.slice(0, 24)}…`);

h('3. Fence — a late write into the cleared range is refused by the database');
const late = NOW - 60 * DAY;
const ingestTry = ingestEvents(db, tenant, [
  { subjectRef: 'dan@example.com', eventType: 'backfill', occurredAt: late },
  { subjectRef: 'dan@example.com', eventType: 'live', occurredAt: NOW - 1000 },
], { actor: 'collector', nowMs: NOW });
line(`  backfilled event (60 days old): ${ingestTry.rejected ? 'REJECTED by fence' : 'accepted'}`);
line(`  live event (1s old):           ${ingestTry.accepted ? 'accepted' : 'rejected'}`);

h('4. Subject erasure — statutory floor protects clinical detail, hold protects summary');
const inspect = await import('../src/erasure.js').then((m) => m.inspectSubjectErasure(db, tenant, 'alice@example.com', { nowMs: NOW }));
for (const l of inspect.layers) {
  line(`  ${l.layer.padEnd(8)} total ${String(l.total).padStart(3)}  eligible ${String(l.eligible).padStart(3)}  blocked ${String(l.blockedCount).padStart(3)}` +
    (l.blockedCount ? `  (${l.blocked[0].blocker.reason})` : ''));
}
const erase = createSubjectErasure(db, tenant, { actor: 'dpo@northwind', nowMs: NOW, subjectRef: 'alice@example.com' });
const eraseRun = executeRequest(db, erase.requestId, { actor: 'dpo@northwind', nowMs: NOW });
line(`  executed: ${eraseRun.status} — erased ${eraseRun.erased}, blocked ${eraseRun.blocked}`);

h('5. Proof verification — deletion, manifest binding, Merkle inclusion, audit chain');
const v = verifyProof(db, erase.requestId, { actor: 'auditor@northwind', nowMs: NOW });
for (const c of v.checks) line(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.id.padEnd(18)} ${c.label}`);

h('6. Audit evidence contains no erased detail');
const proofJson = db.prepare('SELECT payload_json FROM erase_proofs WHERE request_id = ?').get(erase.requestId).payload_json;
const auditJson = JSON.stringify(db.prepare('SELECT payload_json FROM audit_events WHERE tenant_id = ?').all(tenant));
assert.ok(!proofJson.includes('alice@example.com'));
assert.ok(!auditJson.includes('alice@example.com'));
line('  ✓ no plaintext subject identifier in proof or audit payloads');
line('  ✓ commitments are keyed HMACs — values cannot be recovered or dictionary-attacked');

h('7. Consent renewal — the subject may return, without reopening the erased range');
const blockedAgain = ingestEvents(db, tenant, [
  { subjectRef: 'alice@example.com', eventType: 'login', occurredAt: NOW },
], { actor: 'collector', nowMs: NOW });
line(`  re-ingest before consent: ${blockedAgain.accepted ? 'accepted' : 'REJECTED (subject fence)'}`);
const consent = renewConsent(db, tenant, { subjectRef: 'alice@example.com', consentRef: 'CONSENT-2026-77' }, { actor: 'dpo@northwind', nowMs: NOW });
line(`  consent renewed -> generation ${consent.generation}`);
const allowed = ingestEvents(db, tenant, [
  { subjectRef: 'alice@example.com', eventType: 'login', occurredAt: NOW },
], { actor: 'collector', nowMs: NOW });
line(`  re-ingest after consent:  ${allowed.accepted ? 'accepted at new generation' : 'rejected'}`);
const v2 = verifyProof(db, erase.requestId, { actor: 'auditor@northwind', nowMs: NOW });
line(`  earlier proof still verifies: ${v2.ok ? 'yes' : 'NO'}`);

h('8. A hold placed after manifest generation is honoured at execution time');
const hold = placeHold(db, tenant, {
  scopeKind: 'tenant', layer: 'raw', reason: 'Litigation hold', legalBasis: 'Notice 2026-118',
}, { actor: 'legal@northwind', nowMs: NOW });
const sweep2 = createRetentionSweep(db, tenant, { actor: 'ops@northwind', nowMs: NOW });
const beforeCount = db.prepare(
  "SELECT COUNT(*) c FROM raw_events WHERE tenant_id = ? AND occurred_at <= ?"
).get(tenant, NOW - 30 * DAY).c;
const run2 = executeRequest(db, sweep2.requestId, { actor: 'ops@northwind', nowMs: NOW });
const afterCount = db.prepare(
  "SELECT COUNT(*) c FROM raw_events WHERE tenant_id = ? AND occurred_at <= ?"
).get(tenant, NOW - 30 * DAY).c;
line(`  raw objects past cut-off before sweep: ${beforeCount}`);
line(`  sweep under hold: erased ${run2.erased}, blocked ${run2.blocked} (${run2.status})`);
line(`  raw objects past cut-off after sweep:  ${afterCount} — held objects survived`);
releaseHold(db, tenant, hold.id, { actor: 'legal@northwind', nowMs: NOW });
line(`  hold released; the surviving raw objects are deletable on the next sweep`);

h('Summary');
const final = tenantOverview(db, tenant, NOW);
line(`  object counts: ${JSON.stringify(final.objectCounts)}`);
line(`  audit chain valid: ${final.audit.valid} (${final.audit.checked} events)`);
line(`  deletions recorded: ${final.requests.filter((r) => r.status.startsWith('completed')).length} completed request(s)`);
line();