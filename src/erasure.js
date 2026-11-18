import { LAYERS, TABLE_BY_LAYER, tx, uuid } from './db.js';
import {
  canonicalJson,
  contentCommitment,
  contentDigest,
  keyFingerprint,
  subjectToken as makeSubjectToken,
  proofHash,
  merkleRoot,
  merkleProof,
  verifyMerkleProof,
  sha256Hex,
} from './crypto.js';
import {
  LAYER_LABELS,
  activeHolds,
  cutoffFor,
  getPolicies,
  getPolicyForLayer,
  resolveBlocker,
  scanLayer,
  retentionMs,
} from './policy.js';
import { appendAudit, verifyAuditChain } from './audit.js';

export class HttpError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function tenantKey(db, tenantId) {
  const row = db.prepare('SELECT * FROM tenant_keys WHERE tenant_id = ?').get(tenantId);
  if (!row) throw new HttpError(500, 'missing_tenant_key', 'tenant key not provisioned');
  return row;
}

/** Columns carrying erasable content per layer (digested, never stored). */
const CONTENT_COLUMNS = {
  raw: ['event_type', 'payload_json'],
  detail: ['category', 'amount_cents', 'pii_json'],
  summary: ['category', 'period_start', 'period_end', 'total_cents', 'event_count'],
  cache: ['cache_key', 'payload_json'],
};

const CONTENT_DIGEST_DOMAIN = 'content';

function contentString(layer, row) {
  return canonicalJson(
    Object.fromEntries(CONTENT_COLUMNS[layer].map((c) => [c, row[c] ?? null]))
  );
}

function fieldNames(layer) {
  return CONTENT_COLUMNS[layer].slice();
}

function rowTime(layer, row) {
  return layer === 'summary' ? row.computed_at : layer === 'cache' ? row.created_at : row.occurred_at;
}

// ---------------------------------------------------------------------------
// Dry-run inspection: pending objects and blocking reasons, no writes.
// ---------------------------------------------------------------------------

export function inspectRetentionSweep(db, tenantId, { nowMs }) {
  const policies = getPolicies(db, tenantId);
  const holds = activeHolds(db, tenantId, nowMs);
  const layers = [];
  for (const layer of LAYERS) {
    const policy = policies.find((p) => p.layer === layer);
    const cutoffMs = cutoffFor(policy, nowMs);
    const objects = scanLayer(db, tenantId, layer, { cutoffMs });
    const clearRows = [];
    const blocked = [];
    for (const obj of objects) {
      const blocker = resolveBlocker({
        holds, policy, layer, subjectToken: obj.subjectToken, timeMs: obj.timeMs, nowMs,
        enforceStatutory: false,
      });
      if (blocker) blocked.push({ objectRef: obj.objectRef, timeMs: obj.timeMs, blocker });
      else clearRows.push(obj);
    }
    layers.push({
      layer,
      label: LAYER_LABELS[layer],
      cutoffMs,
      retentionMs: retentionMs(policy),
      total: objects.length,
      eligible: clearRows.length,
      blockedCount: blocked.length,
      blocked: blocked.slice(0, 100),
      newestEligibleMs: clearRows.length ? clearRows[clearRows.length - 1].timeMs : null,
    });
  }
  return { layers, totalEligible: layers.reduce((a, l) => a + l.eligible, 0) };
}

export function inspectSubjectErasure(db, tenantId, subjectRef, { nowMs }) {
  const key = tenantKey(db, tenantId);
  const token = makeSubjectToken(key.proof_key, subjectRef);
  const policies = getPolicies(db, tenantId);
  const holds = activeHolds(db, tenantId, nowMs);
  const layers = [];
  for (const layer of LAYERS) {
    const policy = policies.find((p) => p.layer === layer);
    const objects = scanLayer(db, tenantId, layer, { subjectToken: token });
    const clearRows = [];
    const blocked = [];
    for (const obj of objects) {
      const blocker = resolveBlocker({
        holds, policy, layer, subjectToken: obj.subjectToken, timeMs: obj.timeMs, nowMs,
      });
      if (blocker) blocked.push({ objectRef: obj.objectRef, timeMs: obj.timeMs, blocker });
      else clearRows.push(obj);
    }
    layers.push({
      layer,
      label: LAYER_LABELS[layer],
      total: objects.length,
      eligible: clearRows.length,
      blockedCount: blocked.length,
      blocked: blocked.slice(0, 100),
    });
  }
  return {
    subjectToken: token,
    layers,
    totalEligible: layers.reduce((a, l) => a + l.eligible, 0),
    totalBlocked: layers.reduce((a, l) => a + l.blockedCount, 0),
  };
}

// ---------------------------------------------------------------------------
// Create a request: snapshot scope into an immutable, hash-addressed manifest.
// ---------------------------------------------------------------------------

export function createRetentionSweep(db, tenantId, { actor, nowMs, layers: requestedLayers = LAYERS }) {
  return createRequest(db, tenantId, {
    kind: 'retention_sweep', actor, nowMs, requestedLayers, subjectToken: null,
  });
}

export function createSubjectErasure(db, tenantId, { actor, nowMs, subjectRef, layers: requestedLayers = LAYERS }) {
  const key = tenantKey(db, tenantId);
  const token = makeSubjectToken(key.proof_key, subjectRef);
  return createRequest(db, tenantId, {
    kind: 'subject_erasure', actor, nowMs, requestedLayers, subjectToken: token,
  });
}

/**
 * The manifest is the scope inventory. Each item records only opaque refs,
 * timestamps, field *names* and the blocking decision - never field values.
 */
function createRequest(db, tenantId, { kind, actor, nowMs, requestedLayers, subjectToken }) {
  const key = tenantKey(db, tenantId);
  const policies = getPolicies(db, tenantId);
  const holds = activeHolds(db, tenantId, nowMs);

  const layers = [];
  for (const layer of requestedLayers) {
    const policy = policies.find((p) => p.layer === layer);
    if (!policy) throw new HttpError(400, 'unknown_layer', `unknown layer ${layer}`);
    const cutoffMs = kind === 'retention_sweep' ? cutoffFor(policy, nowMs) : null;
    const objects = kind === 'retention_sweep'
      ? scanLayer(db, tenantId, layer, { cutoffMs })
      : scanLayer(db, tenantId, layer, { subjectToken });
    const items = objects.map((obj) => ({
      layer,
      objectRef: obj.objectRef,
      timeMs: obj.timeMs,
      fields: fieldNames(layer),
      blocker: resolveBlocker({
        holds, policy, layer, subjectToken: obj.subjectToken, timeMs: obj.timeMs, nowMs,
        // Retention sweeps only touch already-aged data. A subject erasure
        // must additionally respect statutory minimum retention.
        enforceStatutory: kind === 'subject_erasure',
      }),
    }));
    layers.push({
      layer,
      label: LAYER_LABELS[layer],
      policy: {
        version: policy.version,
        retentionValue: policy.retentionValue,
        retentionUnit: policy.retentionUnit,
        statutoryMinDays: policy.statutoryMinDays,
        statutoryBasis: policy.statutoryBasis,
      },
      cutoffMs,
      itemCount: items.length,
      items,
    });
  }

  const manifestBody = {
    version: 1,
    tenantId,
    kind,
    generatedAt: nowMs,
    requestedBy: actor,
    subjectToken,
    layers: layers.map((l) => ({
      layer: l.layer,
      cutoffMs: l.cutoffMs,
      policyVersion: l.policy.version,
      items: l.items.map((i) => ({
        objectRef: i.objectRef,
        timeMs: i.timeMs,
        fields: i.fields,
        blocked: Boolean(i.blocker),
        blockReason: i.blocker ? i.blocker.reason : null,
        blockRef: i.blocker ? i.blocker.ref ?? null : null,
      })),
    })),
  };
  const manifestHash = sha256Hex(canonicalJson(manifestBody));
  const requestId = uuid('req');
  const manifestId = uuid('man');
  const total = layers.reduce((a, l) => a + l.items.length, 0);
  const blockedCount = layers.reduce((a, l) => a + l.items.filter((i) => i.blocker).length, 0);
  // A request whose entire scope is blocked has nothing to execute. It is
  // created (so the blocked scope is on record) but parked as 'blocked' until a
  // hold is released; executeRequest accepts it and re-evaluates then.
  const initialStatus = total > 0 && blockedCount === total ? 'blocked' : 'awaiting_execution';

  tx(db, () => {
    db.prepare(
      `INSERT INTO erase_requests
        (id, tenant_id, kind, status, requested_by, requested_at, cutoff_ms,
         manifest_id, manifest_hash, item_total, item_blocked)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(requestId, tenantId, kind, initialStatus, actor, nowMs, nowMs, manifestId, manifestHash, total, blockedCount);

    db.prepare(
      `INSERT INTO erase_manifests (id, request_id, tenant_id, payload_json, manifest_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(manifestId, requestId, tenantId, canonicalJson(manifestBody), manifestHash, nowMs);

    const insertItem = db.prepare(
      `INSERT INTO erase_items
        (request_id, layer, object_ref, occurred_at, subject_token, state, block_reason, block_ref)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const layer of layers) {
      for (const item of layer.items) {
        insertItem.run(
          requestId, layer.layer, item.objectRef, item.timeMs,
          kind === 'subject_erasure' ? subjectToken : null,
          item.blocker ? 'blocked' : 'pending',
          item.blocker ? item.blocker.reason : null,
          item.blocker ? item.blocker.ref ?? null : null
        );
      }
    }

    appendAudit(db, {
      tenantId, requestId, type: 'erase.request_created', actor, at: nowMs,
      payload: {
        kind, manifestHash, manifestId, itemTotal: total, alreadyBlocked: blockedCount,
        layers: layers.map((l) => ({ layer: l.layer, items: l.itemCount, cutoffMs: l.cutoffMs })),
        keyFingerprint: keyFingerprint(key.proof_key),
      },
    });

    // Fences are opened in the same transaction that freezes the scope. That
    // closes the gap between "manifest was taken" and "deletion started": once
    // the request exists, a concurrent writer cannot slip an object into the
    // range the manifest just enumerated.
    const opened = openRequestFences(db, { requestId, kind, manifestBody, tenantId, nowMs });
    appendAudit(db, {
      tenantId, requestId, type: 'erase.fences_opened', actor, at: nowMs,
      payload: {
        atCreation: true,
        fences: opened.map((f) => ({ fenceId: f.id, layer: f.layer, kind: f.kind, cutoffMs: f.cutoffMs })),
      },
    });
  });

  return { requestId, manifestId, manifestHash, itemTotal: total, blockedCount };
}

// ---------------------------------------------------------------------------
// Fences
// ---------------------------------------------------------------------------

/**
 * A fence never loosens: re-opening merges by taking max(cutoff) and
 * max(generation). Only the trigger's own row is written, so concurrent
 * requests converge on the strictest fence.
 */
function openFence(db, { tenantId, layer, kind, cutoffMs = 0, maxGeneration = 1, subjectToken = null, requestId, nowMs }) {
  const existing = kind === 'watermark'
    ? db.prepare("SELECT * FROM fences WHERE tenant_id = ? AND layer = ? AND kind = 'watermark'").get(tenantId, layer)
    : db.prepare("SELECT * FROM fences WHERE tenant_id = ? AND layer = ? AND kind = 'subject' AND subject_token = ?")
        .get(tenantId, layer, subjectToken);

  if (existing) {
    const nextCutoff = Math.max(existing.cutoff_ms, Number(cutoffMs) || 0);
    const nextGen = Math.max(existing.max_generation, Number(maxGeneration) || 1);
    db.prepare('UPDATE fences SET cutoff_ms = ?, max_generation = ?, updated_at = ? WHERE id = ?')
      .run(nextCutoff, nextGen, nowMs, existing.id);
    return { id: existing.id, layer, kind, cutoffMs: nextCutoff, maxGeneration: nextGen };
  }
  const id = uuid('fnc');
  db.prepare(
    `INSERT INTO fences (id, tenant_id, layer, kind, cutoff_ms, max_generation, subject_token,
                         request_id, reason, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id, tenantId, layer, kind, Number(cutoffMs) || 0, Number(maxGeneration) || 1,
    subjectToken, requestId,
    kind === 'watermark' ? 'retention_erasure' : 'subject_erasure', nowMs, nowMs
  );
  return { id, layer, kind, cutoffMs: Number(cutoffMs) || 0, maxGeneration: Number(maxGeneration) || 1 };
}

/**
 * Open fences for a request before deleting anything:
 *   retention sweep -> per-layer watermark at the policy cutoff
 *   subject erasure -> per-layer subject fence at the subject's generation
 * The subject fence stops re-ingestion of that subject at the erased
 * generation; a consent renewal raises the generation and lifts it.
 */
function openRequestFences(db, { requestId, kind, manifestBody, tenantId, nowMs }) {
  const opened = [];
  for (const layer of manifestBody.layers) {
    if (kind === 'retention_sweep') {
      opened.push(openFence(db, {
        tenantId, layer: layer.layer, kind: 'watermark',
        cutoffMs: layer.cutoffMs, requestId, nowMs,
      }));
    } else {
      const gen = db.prepare(
        'SELECT generation FROM subject_consents WHERE tenant_id = ? AND subject_token = ?'
      ).get(tenantId, manifestBody.subjectToken)?.generation ?? 1;
      opened.push(openFence(db, {
        tenantId, layer: layer.layer, kind: 'subject',
        subjectToken: manifestBody.subjectToken, maxGeneration: gen,
        requestId, nowMs,
      }));
    }
  }
  return opened;
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

export function executeRequest(db, requestId, { actor, nowMs, batchSize = 100 }) {
  const req = db.prepare('SELECT * FROM erase_requests WHERE id = ?').get(requestId);
  if (!req) throw new HttpError(404, 'request_not_found', 'no such request');
  if (!['awaiting_execution', 'blocked', 'failed'].includes(req.status)) {
    throw new HttpError(409, 'invalid_state', `request is ${req.status} and cannot be executed`);
  }
  const manifest = db.prepare('SELECT * FROM erase_manifests WHERE id = ?').get(req.manifest_id);
  if (!manifest) throw new HttpError(500, 'manifest_missing', 'manifest row missing');
  const manifestBody = JSON.parse(manifest.payload_json);
  const tenantId = req.tenant_id;
  const key = tenantKey(db, tenantId);
  const holds = activeHolds(db, tenantId, nowMs);

  const fences = tx(db, () => {
    db.prepare("UPDATE erase_requests SET status = 'running', started_at = ? WHERE id = ?")
      .run(nowMs, requestId);
    // Fences already exist for requests created through createRequest. This
    // re-open is idempotent and only tightens, which matters for requests that
    // were retried after a failure or created before fencing-at-creation.
    const opened = openRequestFences(db, { requestId, kind: req.kind, manifestBody, tenantId, nowMs });
    appendAudit(db, {
      tenantId, requestId, type: 'erase.fences_opened', actor, at: nowMs,
      payload: {
        atExecution: true,
        fences: opened.map((f) => ({ fenceId: f.id, layer: f.layer, kind: f.kind, cutoffMs: f.cutoffMs })),
      },
    });
    return opened;
  });

  let itemErased = 0;
  let itemSkipped = 0;
  try {
    for (const layerManifest of manifestBody.layers) {
      // Every request starts clean: items left 'pending' or 'blocked' by a
      // previous failed attempt are re-evaluated against current holds.
      db.prepare(
        "UPDATE erase_items SET state = 'pending', block_reason = NULL, block_ref = NULL WHERE request_id = ? AND layer = ? AND state = 'blocked'"
      ).run(requestId, layerManifest.layer);
      const pending = db
        .prepare("SELECT * FROM erase_items WHERE request_id = ? AND layer = ? AND state = 'pending' ORDER BY id")
        .all(requestId, layerManifest.layer);

      for (let offset = 0; offset < pending.length; offset += batchSize) {
        const slice = pending.slice(offset, offset + batchSize);
        const outcome = tx(db, () => eraseBatch(db, {
          req, tenantId, key, layer: layerManifest.layer, items: slice, holds, nowMs,
        }));
        itemErased += outcome.erased;
        itemSkipped += outcome.skipped;
      }
    }

    // Prefer the durable item table over the in-memory running totals: a
    // retried request must report the state of the whole request.
    const totals = Object.fromEntries(
      db.prepare('SELECT state, COUNT(*) c FROM erase_items WHERE request_id = ? GROUP BY state')
        .all(requestId).map((r) => [r.state, r.c])
    );
    itemErased = totals.erased ?? 0;
    itemSkipped = totals.skipped ?? 0;
    const blockedTotal = totals.blocked ?? 0;
    const finalStatus = blockedTotal > 0 ? 'completed_with_exceptions' : 'completed';

    const proof = tx(db, () => {
      db.prepare(
        `UPDATE erase_requests SET status = ?, finished_at = ?, item_erased = ?, item_skipped = ?, item_blocked = ?
         WHERE id = ?`
      ).run(finalStatus, nowMs, itemErased, itemSkipped, blockedTotal, requestId);

      const built = buildProof(db, {
        requestId, tenantId, key, req, manifestBody, actor, nowMs,
        counts: { erased: itemErased, skipped: itemSkipped, blocked: blockedTotal },
      });
      appendAudit(db, {
        tenantId, requestId, type: 'erase.request_completed', actor, at: nowMs,
        payload: {
          status: finalStatus, erased: itemErased, skipped: itemSkipped, blocked: blockedTotal,
          proofId: built.proofId, merkleRoot: built.merkleRoot, proofHash: built.proofHash,
        },
      });
      return built;
    });

    return {
      requestId, status: finalStatus, erased: itemErased, skipped: itemSkipped, blocked: blockedTotal,
      proof, fences,
    };
  } catch (err) {
    tx(db, () => {
      db.prepare("UPDATE erase_requests SET status = 'failed', error = ?, finished_at = ? WHERE id = ?")
        .run(String(err.message), nowMs, requestId);
      appendAudit(db, {
        tenantId, requestId, type: 'erase.request_failed', actor, at: nowMs,
        payload: { error: String(err.message), erasedSoFar: itemErased },
      });
    });
    throw err;
  }
}

/**
 * Delete one batch. Deletion of a row and the commitment to its content
 * happen in the same transaction, so there is never a gap where an object is
 * gone but unaccounted for.
 */
function eraseBatch(db, { req, tenantId, key, layer, items, holds, nowMs }) {
  const table = TABLE_BY_LAYER[layer];
  const del = db.prepare(`DELETE FROM ${table} WHERE id = ? AND tenant_id = ?`);
  const getRow = db.prepare(`SELECT * FROM ${table} WHERE id = ? AND tenant_id = ?`);
  const markErased = db.prepare(
    "UPDATE erase_items SET state = 'erased', erased_at = ?, batch_no = ? WHERE id = ?"
  );
  const markSkipped = db.prepare(
    "UPDATE erase_items SET state = 'skipped', block_reason = ?, erased_at = ? WHERE id = ?"
  );
  const markBlocked = db.prepare(
    "UPDATE erase_items SET state = 'blocked', block_reason = ?, block_ref = ? WHERE id = ?"
  );

  const batchNo = db
    .prepare('SELECT COALESCE(MAX(seq),0)+1 AS n FROM erase_batches WHERE request_id = ?')
    .get(req.id).n;
  const policy = getPolicyForLayer(db, tenantId, layer);
  const leaves = [];
  let erased = 0;
  let skipped = 0;

  for (const item of items) {
    const id = Number(item.object_ref.split(':')[1]);
    const row = getRow.get(id, tenantId);
    if (!row) {
      markSkipped.run('already_absent', nowMs, item.id);
      skipped += 1;
      continue;
    }
    // Re-check at execution time: a hold placed after manifest generation
    // must still be honoured.
    const timeMs = rowTime(layer, row);
    const blocker = resolveBlocker({
      holds, policy, layer, subjectToken: row.subject_token, timeMs, nowMs,
      enforceStatutory: req.kind === 'subject_erasure',
    });
    if (blocker) {
      markBlocked.run(blocker.reason, blocker.ref ?? null, item.id);
      continue;
    }

    const digest = contentDigest(key.proof_key, `${CONTENT_DIGEST_DOMAIN}\u0000${contentString(layer, row)}`);
    const commitment = contentCommitment(key.proof_key, {
      layer, objectRef: item.object_ref, contentDigest: digest,
    });
    del.run(id, tenantId);
    markErased.run(nowMs, batchNo, item.id);
    erased += 1;
    leaves.push({ layer, objectRef: item.object_ref, commitment });
  }

  const batchRoot = commitLeaves(db, req.id, batchNo, leaves);
  const prevRoot = db
    .prepare('SELECT commitment_root FROM erase_batches WHERE request_id = ? ORDER BY seq DESC LIMIT 1')
    .get(req.id)?.commitment_root ?? '';

  // Nothing deleted in this batch -> no batch row, just the item state.
  if (leaves.length > 0) {
    db.prepare(
      `INSERT INTO erase_batches (request_id, layer, seq, item_count, commitment_root, prev_root, committed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(req.id, layer, batchNo, leaves.length, batchRoot, prevRoot, nowMs);
  }

  appendAudit(db, {
    tenantId, requestId: req.id, type: 'erase.batch_committed',
    actor: req.requested_by, at: nowMs,
    payload: { layer, batchNo, erased, skipped, leaves: leaves.length, commitmentRoot: batchRoot, prevRoot },
  });

  return { erased, skipped, batchRoot };
}

function commitLeaves(db, requestId, batchNo, leaves) {
  if (leaves.length === 0) return merkleRoot([]);
  const nextIndex = db
    .prepare('SELECT COALESCE(MAX(leaf_index), -1) + 1 AS n FROM erase_proof_leaves WHERE request_id = ?')
    .get(requestId).n;
  const insert = db.prepare(
    `INSERT INTO erase_proof_leaves (request_id, leaf_index, layer, object_ref, commitment, batch_no)
     VALUES (?, ?, ?, ?, ?, ?)`
  );
  leaves.forEach((leaf, i) => {
    insert.run(requestId, nextIndex + i, leaf.layer, leaf.objectRef, leaf.commitment, batchNo);
  });
  return merkleRoot(leaves.map((l) => l.commitment));
}

// ---------------------------------------------------------------------------
// Proof document
// ---------------------------------------------------------------------------

function buildProof(db, { requestId, tenantId, key, req, manifestBody, actor, nowMs, counts }) {
  const leaves = db
    .prepare('SELECT leaf_index, layer, object_ref, commitment FROM erase_proof_leaves WHERE request_id = ? ORDER BY leaf_index')
    .all(requestId);
  const batches = db
    .prepare('SELECT * FROM erase_batches WHERE request_id = ? ORDER BY seq')
    .all(requestId)
    .map((b) => ({
      seq: b.seq, layer: b.layer, itemCount: b.item_count,
      commitmentRoot: b.commitment_root, prevRoot: b.prev_root,
    }));

  const commitments = leaves.map((l) => l.commitment);
  const root = merkleRoot(commitments);
  // Store inclusion paths for a bounded sample so the evidence stays
  // inspectable without inflating the bundle for very large sweeps.
  const paths = sampleIndexes(commitments.length, 32).map((idx) => ({
    leafIndex: idx,
    objectRef: leaves[idx].object_ref,
    layer: leaves[idx].layer,
    commitment: leaves[idx].commitment,
    path: merkleProof(commitments, idx),
  }));

  const blocked = db
    .prepare(`SELECT layer, object_ref, block_reason, block_ref FROM erase_items
              WHERE request_id = ? AND state = 'blocked' ORDER BY id`)
    .all(requestId)
    .map((r) => ({ layer: r.layer, objectRef: r.object_ref, reason: r.block_reason, holdRef: r.block_ref }));

  const holdsClaimed = db
    .prepare(`SELECT DISTINCT h.* FROM legal_holds h
              JOIN erase_items i ON i.block_ref = h.id
              WHERE i.request_id = ? AND i.state = 'blocked'`)
    .all(requestId)
    .map((h) => ({
      holdId: h.id, scopeKind: h.scope_kind, legalBasis: h.legal_basis, reason: h.reason,
      placedBy: h.placed_by, placedAt: h.placed_at, expiresAt: h.expires_at,
    }));

  const skipped = db
    .prepare(`SELECT layer, block_reason, COUNT(*) c FROM erase_items
              WHERE request_id = ? AND state = 'skipped' GROUP BY layer, block_reason`)
    .all(requestId)
    .map((r) => ({ layer: r.layer, reason: r.block_reason, count: r.c }));

  const proofBody = {
    version: 1,
    proofId: uuid('prf'),
    requestId,
    tenantId,
    kind: req.kind,
    generatedAt: nowMs,
    generatedBy: actor,
    manifest: { id: req.manifest_id, hash: req.manifest_hash },
    keyFingerprint: keyFingerprint(key.proof_key),
    counts: {
      erased: counts.erased,
      blocked: counts.blocked,
      skipped: counts.skipped ?? 0,
      proofLeaves: leaves.length,
    },
    layers: manifestBody.layers.map((l) => ({
      layer: l.layer, cutoffMs: l.cutoffMs, policyVersion: l.policyVersion,
    })),
    excluded: { blocked, skipped, holdsClaimed },
    leafCommitments: commitments,
    merkleRoot: root,
    batches,
    samplePaths: paths,
  };
  const hash = proofHash(proofBody);
  proofBody.proofHash = hash;

  db.prepare(
    `INSERT INTO erase_proofs (id, request_id, version, payload_json, proof_hash, merkle_root, status, created_at)
     VALUES (?, ?, 1, ?, ?, ?, 'unverified', ?)`
  ).run(proofBody.proofId, requestId, canonicalJson(proofBody), hash, root, nowMs);
  db.prepare('UPDATE erase_requests SET proof_id = ? WHERE id = ?').run(proofBody.proofId, requestId);
  appendAudit(db, {
    tenantId, requestId, type: 'proof.generated', actor, at: nowMs,
    payload: { proofId: proofBody.proofId, proofHash: hash, merkleRoot: root, leaves: leaves.length },
  });

  return { proofId: proofBody.proofId, proofHash: hash, merkleRoot: root, leafCount: leaves.length };
}

function sampleIndexes(n, max) {
  if (n <= max) return Array.from({ length: n }, (_, i) => i);
  const step = Math.ceil(n / max);
  const out = [];
  for (let i = 0; i < n; i += step) out.push(i);
  return out;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export function verifyProof(db, requestId, { actor, nowMs }) {
  const row = db
    .prepare('SELECT * FROM erase_proofs WHERE request_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1')
    .get(requestId);
  if (!row) throw new HttpError(404, 'proof_not_found', 'no proof for this request');
  const body = JSON.parse(row.payload_json);
  const key = tenantKey(db, body.tenantId);
  const checks = [];

  const recomputed = proofHash(body);
  checks.push({
    id: 'proof_hash',
    label: 'Proof document hash matches its canonical content',
    ok: recomputed === body.proofHash,
    detail: recomputed === body.proofHash ? body.proofHash : `expected ${body.proofHash}, got ${recomputed}`,
  });

  const manifest = db.prepare('SELECT * FROM erase_manifests WHERE id = ?').get(body.manifest.id);
  const manifestOk = Boolean(manifest) &&
    sha256Hex(canonicalJson(JSON.parse(manifest.payload_json))) === body.manifest.hash;
  checks.push({
    id: 'manifest_binding',
    label: 'Manifest hash is unchanged since generation',
    ok: manifestOk,
    detail: body.manifest.hash,
  });

  const counts = db
    .prepare('SELECT state, COUNT(*) c FROM erase_items WHERE request_id = ? GROUP BY state')
    .all(requestId);
  const byState = Object.fromEntries(counts.map((c) => [c.state, c.c]));
  const total = Object.values(byState).reduce((a, b) => a + b, 0);
  const accounted = (byState.erased ?? 0) + (byState.blocked ?? 0) + (byState.skipped ?? 0);
  checks.push({
    id: 'counts_reconcile',
    label: 'Erased + blocked + skipped accounts for every manifest item',
    ok: total === accounted && (byState.pending ?? 0) === 0,
    detail: { total, byState },
  });

  const stillPresent = db
    .prepare("SELECT layer, object_ref FROM erase_items WHERE request_id = ? AND state = 'erased'")
    .all(requestId)
    .filter((it) => Boolean(
      db.prepare(`SELECT 1 FROM ${TABLE_BY_LAYER[it.layer]} WHERE id = ?`)
        .get(Number(it.object_ref.split(':')[1]))
    ));
  checks.push({
    id: 'objects_absent',
    label: 'Every erased object is absent from the warehouse',
    ok: stillPresent.length === 0,
    detail: stillPresent.length === 0 ? 'all absent' : stillPresent,
  });

  const leaves = db
    .prepare('SELECT commitment FROM erase_proof_leaves WHERE request_id = ? ORDER BY leaf_index')
    .all(requestId)
    .map((r) => r.commitment);
  const recomputedRoot = merkleRoot(leaves);
  checks.push({
    id: 'merkle_root',
    label: 'Merkle root recomputes over the committed leaves',
    ok: recomputedRoot === body.merkleRoot,
    detail: recomputedRoot,
  });

  const pathsOk = body.samplePaths.every((p) => verifyMerkleProof(p.path) && p.path.root === body.merkleRoot);
  checks.push({
    id: 'inclusion_paths',
    label: `Sampled inclusion paths verify (${body.samplePaths.length} leaves)`,
    ok: pathsOk,
    detail: pathsOk ? 'all sampled leaves prove inclusion' : 'path mismatch',
  });

  checks.push({
    id: 'key_binding',
    label: 'Proof was produced with this tenant’s current key',
    ok: keyFingerprint(key.proof_key) === body.keyFingerprint,
    detail: body.keyFingerprint,
  });

  const fences = db.prepare('SELECT * FROM fences WHERE request_id = ?').all(requestId);
  checks.push({
    id: 'fences_active',
    label: 'Erasure fences remain in force for the cleared ranges',
    ok: fences.length > 0,
    detail: fences.map((f) => ({
      layer: f.layer, kind: f.kind, cutoffMs: f.cutoff_ms, maxGeneration: f.max_generation,
    })),
  });

  // The strongest statement: no object now present in the cleared range is
  // unaccounted for. Anything inside the fence must be either an item the
  // request knowingly blocked (legal hold / statutory floor) or a row that
  // arrived after the fence and is therefore outside the manifest's scope.
  const reentries = [];
  for (const layer of LAYERS) {
    const layerFence = fences.find((f) => f.layer === layer && f.kind === 'watermark');
    const subjectFence = fences.find((f) => f.layer === layer && f.kind === 'subject');
    if (!layerFence && !subjectFence) continue;
    const timeCol = TABLE_BY_LAYER[layer] === 'summary_rollups' ? 'computed_at'
      : TABLE_BY_LAYER[layer] === 'cache_entries' ? 'created_at' : 'occurred_at';
    // A layer without a watermark (a subject erasure) has no time bound; its
    // fence is by subject, so every row for that subject is in scope.
    const timeBound = layerFence ? layerFence.cutoff_ms : Number.POSITIVE_INFINITY;
    const candidates = db.prepare(
      `SELECT * FROM ${TABLE_BY_LAYER[layer]} WHERE tenant_id = ?`
    ).all(body.tenantId).filter((row) => {
      if (row[timeCol] > timeBound) return false;
      if (subjectFence) return row.subject_token === subjectFence.subject_token;
      return true;
    });
    const accountedFor = new Set(
      db.prepare('SELECT object_ref FROM erase_items WHERE request_id = ?')
        .all(requestId).map((r) => r.object_ref)
    );
    for (const row of candidates) {
      const ref = `${layer}:${row.id}`;
      if (accountedFor.has(ref)) continue;
      // A row that exists only because consent was renewed and raised the
      // generation sits above the fence's max_generation and is legitimate.
      if (subjectFence && row.generation > subjectFence.max_generation) continue;
      reentries.push(ref);
    }
  }
  checks.push({
    id: 'no_reentry',
    label: 'No unaccounted object sits inside a cleared range',
    ok: reentries.length === 0,
    detail: reentries.length === 0 ? 'cleared ranges hold only accounted-for rows or blockers' : reentries.slice(0, 20),
  });

  const chain = verifyAuditChain(db, body.tenantId);
  checks.push({
    id: 'audit_chain',
    label: 'Tenant audit hash chain verifies',
    ok: chain.valid,
    detail: chain,
  });

  const allOk = checks.every((c) => c.ok);
  const verification = { verifiedAt: nowMs, verifiedBy: actor, ok: allOk, checks };
  db.prepare('UPDATE erase_proofs SET status = ?, verified_at = ?, verification_json = ? WHERE id = ?')
    .run(allOk ? 'verified' : 'failed', nowMs, canonicalJson(verification), row.id);
  appendAudit(db, {
    tenantId: body.tenantId, requestId,
    type: allOk ? 'proof.verified' : 'proof.verification_failed',
    actor, at: nowMs,
    payload: { proofId: row.id, checks: checks.map((c) => ({ id: c.id, ok: c.ok })) },
  });

  return { proofId: row.id, proofHash: body.proofHash, merkleRoot: body.merkleRoot, ...verification };
}
