import { canonicalJson, sha256Hex } from './crypto.js';
import { tx } from './db.js';

/**
 * Append-only, per-tenant hash chain. Each event commits to the previous
 * event's hash, so removing or reordering any event breaks verification.
 * Payloads are constrained to opaque metadata (opaque refs, counts, reasons);
 * callers must never place subject plaintext or erased field values here.
 */
export function appendAudit(db, { tenantId, requestId = null, type, actor, payload = {}, at }) {
  const prev = db
    .prepare('SELECT hash FROM audit_events WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1')
    .get(tenantId);
  const prevHash = prev ? prev.hash : 'GENESIS';
  const body = { tenantId, requestId, type, actor, at, payload };
  const hash = sha256Hex(canonicalJson(body) + '\u0000' + prevHash);
  const info = db
    .prepare(
      `INSERT INTO audit_events (tenant_id, request_id, type, at, actor, payload_json, prev_hash, hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(tenantId, requestId, type, at, actor, canonicalJson(payload), prevHash, hash);
  return { seq: Number(info.lastInsertRowid), hash, prevHash };
}

export function listAudit(db, tenantId, { limit = 200, requestId = null } = {}) {
  const rows = requestId
    ? db.prepare(
        `SELECT * FROM audit_events WHERE tenant_id = ? AND request_id = ? ORDER BY seq ASC`
      ).all(tenantId, requestId)
    : db.prepare(
        `SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY seq DESC LIMIT ?`
      ).all(tenantId, limit).reverse();
  return rows.map((r) => ({
    seq: r.seq,
    tenantId: r.tenant_id,
    requestId: r.request_id,
    type: r.type,
    at: r.at,
    actor: r.actor,
    payload: JSON.parse(r.payload_json),
    prevHash: r.prev_hash,
    hash: r.hash,
  }));
}

/** Recompute the chain from the beginning and report the first break. */
export function verifyAuditChain(db, tenantId) {
  const rows = db
    .prepare('SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY seq ASC')
    .all(tenantId);
  let prevHash = 'GENESIS';
  for (const r of rows) {
    const payload = JSON.parse(r.payload_json);
    const body = {
      tenantId: r.tenant_id,
      requestId: r.request_id,
      type: r.type,
      actor: r.actor,
      at: r.at,
      payload,
    };
    const expected = sha256Hex(canonicalJson(body) + '\u0000' + prevHash);
    if (r.prev_hash !== prevHash) {
      return { valid: false, checked: r.seq, brokenAt: r.seq, reason: 'prev_hash_mismatch' };
    }
    if (expected !== r.hash) {
      return { valid: false, checked: r.seq, brokenAt: r.seq, reason: 'hash_mismatch' };
    }
    prevHash = r.hash;
  }
  return { valid: true, checked: rows.length, head: prevHash };
}

/** Record + commit helper so audit writes join the surrounding transaction. */
export function auditInTx(db, event) {
  return appendAudit(db, event);
}

export { tx };
