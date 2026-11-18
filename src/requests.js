import { LAYERS } from './db.js';
import { HttpError } from './erasure.js';
import { requestSummary } from './services.js';

export function listRequests(db, tenantId, { limit = 50 } = {}) {
  return db
    .prepare('SELECT * FROM erase_requests WHERE tenant_id = ? ORDER BY requested_at DESC, rowid DESC LIMIT ?')
    .all(tenantId, limit)
    .map(requestSummary);
}

export function getRequest(db, tenantId, requestId) {
  const r = db.prepare('SELECT * FROM erase_requests WHERE id = ? AND tenant_id = ?').get(requestId, tenantId);
  if (!r) throw new HttpError(404, 'request_not_found', 'no such request');
  const manifest = db.prepare('SELECT * FROM erase_manifests WHERE id = ?').get(r.manifest_id);
  const body = manifest ? JSON.parse(manifest.payload_json) : null;

  const items = db
    .prepare('SELECT * FROM erase_items WHERE request_id = ? ORDER BY layer, occurred_at ASC, id ASC')
    .all(requestId)
    .map((i) => ({
      id: i.id,
      layer: i.layer,
      objectRef: i.object_ref,
      occurredAt: i.occurred_at,
      state: i.state,
      blockReason: i.block_reason,
      blockRef: i.block_ref,
      batchNo: i.batch_no,
      erasedAt: i.erased_at,
    }));

  const byLayer = LAYERS.map((layer) => {
    const layerItems = items.filter((i) => i.layer === layer);
    const layerManifest = body?.layers.find((l) => l.layer === layer);
    return {
      layer,
      cutoffMs: layerManifest?.cutoffMs ?? null,
      policyVersion: layerManifest?.policyVersion ?? null,
      total: layerItems.length,
      erased: layerItems.filter((i) => i.state === 'erased').length,
      blocked: layerItems.filter((i) => i.state === 'blocked').length,
      skipped: layerItems.filter((i) => i.state === 'skipped').length,
      pending: layerItems.filter((i) => i.state === 'pending').length,
    };
  }).filter((l) => l.total > 0 || body?.layers.some((m) => m.layer === l.layer));

  const batches = db
    .prepare('SELECT * FROM erase_batches WHERE request_id = ? ORDER BY seq')
    .all(requestId)
    .map((b) => ({
      seq: b.seq, layer: b.layer, itemCount: b.item_count,
      commitmentRoot: b.commitment_root, prevRoot: b.prev_root, committedAt: b.committed_at,
    }));

  const proof = db
    .prepare('SELECT id, proof_hash, merkle_root, status, verified_at, verification_json, payload_json, created_at FROM erase_proofs WHERE request_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1')
    .get(requestId);

  const progress = {
    total: items.length,
    settled: items.filter((i) => i.state !== 'pending').length,
    erased: items.filter((i) => i.state === 'erased').length,
    blocked: items.filter((i) => i.state === 'blocked').length,
    skipped: items.filter((i) => i.state === 'skipped').length,
    pending: items.filter((i) => i.state === 'pending').length,
  };

  const blockers = items
    .filter((i) => i.state === 'blocked')
    .map((i) => ({ objectRef: i.objectRef, layer: i.layer, reason: i.blockReason, holdRef: i.blockRef }));
  const blockerSummary = Object.values(
    blockers.reduce((acc, b) => {
      const key = `${b.reason}\u0000${b.holdRef ?? ''}`;
      acc[key] ??= { reason: b.reason, holdRef: b.holdRef, count: 0, layers: {} };
      acc[key].count += 1;
      acc[key].layers[b.layer] = (acc[key].layers[b.layer] ?? 0) + 1;
      return acc;
    }, {})
  );

  const holdsAffected = db
    .prepare(`SELECT DISTINCT h.* FROM legal_holds h WHERE h.id IN
              (SELECT block_ref FROM erase_items WHERE request_id = ? AND block_ref IS NOT NULL)`)
    .all(requestId)
    .map((h) => ({
      id: h.id, scopeKind: h.scope_kind, legalBasis: h.legal_basis, reason: h.reason,
      status: h.status, expiresAt: h.expires_at,
    }));

  return {
    request: requestSummary(r),
    manifest: body
      ? {
          id: manifest.id,
          hash: manifest.manifest_hash,
          generatedAt: body.generatedAt,
          requestedBy: body.requestedBy,
          subjectToken: body.subjectToken,
          layerCount: body.layers.length,
          itemCount: body.layers.reduce((a, l) => a + l.items.length, 0),
        }
      : null,
    byLayer,
    progress,
    items,
    blockers,
    blockerSummary,
    holdsAffected,
    batches,
    proof: proof
      ? {
          id: proof.id,
          proofHash: proof.proof_hash,
          merkleRoot: proof.merkle_root,
          status: proof.status,
          verifiedAt: proof.verified_at,
          verification: proof.verification_json ? JSON.parse(proof.verification_json) : null,
          createdAt: proof.created_at,
        }
      : null,
  };
}

export function getProof(db, tenantId, requestId) {
  const req = db.prepare('SELECT id FROM erase_requests WHERE id = ? AND tenant_id = ?').get(requestId, tenantId);
  if (!req) throw new HttpError(404, 'request_not_found', 'no such request');
  const row = db
    .prepare('SELECT * FROM erase_proofs WHERE request_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1')
    .get(requestId);
  if (!row) throw new HttpError(404, 'proof_not_found', 'no proof for this request');
  return { ...JSON.parse(row.payload_json), status: row.status, verification: row.verification_json ? JSON.parse(row.verification_json) : null };
}
