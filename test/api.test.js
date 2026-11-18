import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { seed } from '../scripts/seed.js';
import { clock } from '../src/config.js';

const NOW = Date.UTC(2026, 5, 15, 12, 0, 0);
let server;
let baseUrl;
let db;
let tmpDir;

async function req(method, p, body) {
  const res = await fetch(baseUrl + p, {
    method,
    headers: { 'content-type': 'application/json', 'x-actor': 'tester@ops' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json();
  return { status: res.status, data };
}

before(async () => {
  clock.freeze(NOW);
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'retention-test-'));
  const created = createServer({ dbPath: path.join(tmpDir, 'test.db') });
  server = created.server;
  db = created.db;
  seed(db, { nowMs: NOW });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.close();
  clock.unfreeze();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('GET /api/tenants lists seeded tenants', async () => {
  const { status, data } = await req('GET', '/api/tenants');
  assert.equal(status, 200);
  const ids = data.tenants.map((t) => t.id).sort();
  assert.deepEqual(ids, ['atlas', 'lumenpay', 'northwind']);
});

test('overview exposes policy, pending objects and a verified audit chain', async () => {
  const { status, data } = await req('GET', '/api/tenants/northwind/overview');
  assert.equal(status, 200);
  assert.equal(data.policies.length, 4);
  assert.equal(data.audit.valid, true);
  assert.ok(data.pending.length === 4);
  assert.ok(data.keyFingerprint.startsWith('kfp_'));
  // The key itself must never leave the server.
  assert.equal(data.key, undefined);
  assert.ok(!JSON.stringify(data).includes('proof_key'));
});

test('retention sweep returns a manifest and executed proof', async () => {
  const { status, data } = await req('POST', '/api/tenants/atlas/requests', { kind: 'retention_sweep' });
  assert.equal(status, 200);
  assert.ok(data.manifestHash.match(/^[0-9a-f]{64}$/));
  assert.ok(data.execution.erased > 0);
  assert.equal(data.execution.proof.leafCount, data.execution.erased);

  const verify = await req('POST', `/api/tenants/atlas/requests/${data.requestId}/verify`);
  assert.equal(verify.status, 200);
  assert.equal(verify.data.verification.ok, true);
});

test('re-ingesting a cleared range is rejected by the fence', async () => {
  const old = NOW - 60 * 86_400_000;
  const { status, data } = await req('POST', '/api/tenants/atlas/ingest', {
    events: [
      { subjectRef: 'late@x.com', eventType: 'login', occurredAt: old },
      { subjectRef: 'late@x.com', eventType: 'login', occurredAt: NOW - 1000 },
    ],
  });
  assert.equal(status, 200);
  assert.equal(data.accepted, 1);
  assert.equal(data.rejected, 1);

  const rej = await req('GET', '/api/tenants/atlas/rejections');
  assert.ok(rej.data.rejections.length >= 1);
  assert.ok(!JSON.stringify(rej.data).includes('late@x.com'), 'rejections are tokenised');
});

test('subject inspection then erasure blocks statutorily protected detail', async () => {
  const inspect = await req('POST', '/api/tenants/northwind/subjects/inspect', { subjectRef: 'alice@example.com' });
  assert.equal(inspect.status, 200);
  assert.ok(inspect.data.totalEligible > 0);
  assert.ok(inspect.data.layers.some((l) => l.blocked.some((b) => b.blocker.reason === 'statutory_minimum')));

  const erase = await req('POST', '/api/tenants/northwind/requests', {
    kind: 'subject_erasure', subjectRef: 'alice@example.com',
  });
  assert.equal(erase.status, 200);
  assert.equal(erase.data.execution.status, 'completed_with_exceptions');

  const verify = await req('POST', `/api/tenants/northwind/requests/${erase.data.requestId}/verify`);
  assert.equal(verify.data.verification.ok, true);

  // The subject's own row is not recoverable through any public surface.
  const request = await req('GET', `/api/tenants/northwind/requests/${erase.data.requestId}`);
  assert.ok(!JSON.stringify(request.data).includes('alice@example.com'));
});

test('policy update is versioned and rejects an illegal cut-off', async () => {
  const bad = await req('PATCH', '/api/tenants/northwind/policies/detail', {
    retentionValue: 30, retentionUnit: 'days',
  });
  assert.equal(bad.status, 400);
  assert.equal(bad.data.error.code, 'retention_below_statutory');

  const good = await req('PATCH', '/api/tenants/northwind/policies/detail', {
    retentionValue: 500, retentionUnit: 'days',
  });
  assert.equal(good.status, 200);
  assert.equal(good.data.policy.retentionValue, 500);
  assert.equal(good.data.policy.version, 2);
});

test('placing and releasing a hold changes eligibility', async () => {
  const before = await req('POST', '/api/tenants/atlas/subjects/inspect', { subjectRef: 'bob@example.com' });
  const hold = await req('POST', '/api/tenants/atlas/holds', {
    scopeKind: 'subject', subjectRef: 'bob@example.com',
    reason: 'Inquiry', legalBasis: 'Subpoena 12',
  });
  assert.equal(hold.status, 200);

  const afterHold = await req('POST', '/api/tenants/atlas/subjects/inspect', { subjectRef: 'bob@example.com' });
  assert.ok(afterHold.data.totalBlocked >= before.data.totalBlocked);

  const release = await req('POST', `/api/tenants/atlas/holds/${hold.data.hold.id}/release`);
  assert.equal(release.status, 200);
  const afterRelease = await req('POST', '/api/tenants/atlas/subjects/inspect', { subjectRef: 'bob@example.com' });
  assert.equal(afterRelease.data.totalBlocked, before.data.totalBlocked);
});

test('invalid payloads return structured errors', async () => {
  assert.equal((await req('POST', '/api/tenants/atlas/requests', { kind: 'nope' })).status, 400);
  assert.equal((await req('POST', '/api/tenants/atlas/requests', { kind: 'subject_erasure' })).status, 400);
  assert.equal((await req('POST', '/api/tenants/atlas/ingest', { events: [] })).status, 400);
  assert.equal((await req('GET', '/api/tenants/nope/overview')).status, 404);
  assert.equal((await req('GET', '/api/tenants/atlas/requests/req_missing')).status, 404);
});

test('consent renewal allows re-ingestion at a new generation', async () => {
  const first = await req('POST', '/api/tenants/atlas/requests', {
    kind: 'subject_erasure', subjectRef: 'carol@example.com',
  });
  assert.equal(first.status, 200);

  const blocked = await req('POST', '/api/tenants/atlas/ingest', {
    events: [{ subjectRef: 'carol@example.com', eventType: 'login', occurredAt: NOW }],
  });
  assert.equal(blocked.data.accepted, 0);

  const renew = await req('POST', '/api/tenants/atlas/consent', {
    subjectRef: 'carol@example.com', consentRef: 'C-77',
  });
  assert.equal(renew.data.consent.generation, 2);

  const allowed = await req('POST', '/api/tenants/atlas/ingest', {
    events: [{ subjectRef: 'carol@example.com', eventType: 'login', occurredAt: NOW }],
  });
  assert.equal(allowed.data.accepted, 1);

  // The earlier proof still verifies: the new-generation row is not a re-entry.
  const verify = await req('POST', `/api/tenants/atlas/requests/${first.data.requestId}/verify`);
  assert.equal(verify.data.verification.ok, true);
});

test('manifest endpoint returns the frozen scope', async () => {
  const created = await req('POST', '/api/tenants/atlas/requests', {
    kind: 'retention_sweep', execute: false,
  });
  const manifest = await req('GET', `/api/tenants/atlas/requests/${created.data.requestId}/manifest`);
  assert.equal(manifest.status, 200);
  assert.equal(manifest.data.hash, created.data.manifestHash);
  assert.ok(Array.isArray(manifest.data.manifest.layers));
  assert.ok(manifest.data.manifest.layers.every((l) => l.items.every((i) => !('payload' in i))));
});
