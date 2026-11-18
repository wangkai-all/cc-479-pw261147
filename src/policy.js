import { LAYERS, TABLE_BY_LAYER } from './db.js';
import { clock } from './config.js';

const HOUR = 3_600_000;
const DAY = 86_400_000;

export const LAYER_LABELS = {
  raw: 'Raw',
  detail: 'Detail',
  summary: 'Summary',
  cache: 'Cache',
};

/** Column that carries the object's effective timestamp, per layer. */
const TIME_COLUMN = {
  raw: 'occurred_at',
  detail: 'occurred_at',
  summary: 'computed_at',
  cache: 'created_at',
};

const SUBJECT_COLUMN = {
  raw: 'subject_token',
  detail: 'subject_token',
  summary: 'subject_token',
  cache: 'subject_token',
};

export const DEFAULT_POLICY = {
  raw: { retentionValue: 30, retentionUnit: 'days', statutoryMinDays: 0, legalBasis: 'Operational telemetry minimisation', exceptionNote: '' },
  detail: { retentionValue: 180, retentionUnit: 'days', statutoryMinDays: 0, legalBasis: 'Contractual records', exceptionNote: '' },
  summary: { retentionValue: 730, retentionUnit: 'days', statutoryMinDays: 0, legalBasis: 'Aggregate analytics', exceptionNote: '' },
  cache: { retentionValue: 7, retentionUnit: 'days', statutoryMinDays: 0, legalBasis: 'Derived cache, rebuildable', exceptionNote: '' },
};

export function retentionMs(policy) {
  const unit = policy.retentionUnit === 'hours' ? HOUR : DAY;
  return Number(policy.retentionValue) * unit;
}

export function statutoryMs(policy) {
  return Number(policy.statutoryMinDays || 0) * DAY;
}

export function cutoffFor(policy, nowMs = clock.now()) {
  return nowMs - retentionMs(policy);
}

export function getPolicies(db, tenantId) {
  const rows = db
    .prepare(
      `SELECT id, tenant_id, layer, retention_value, retention_unit, legal_basis,
              exception_note, statutory_min_days, statutory_basis, version,
              is_current, effective_from, updated_at
         FROM retention_policies
        WHERE tenant_id = ? AND is_current = 1
        ORDER BY layer`
    )
    .all(tenantId);
  const byLayer = new Map(rows.map((r) => [r.layer, mapPolicy(r)]));
  return LAYERS.map((layer) => {
    const existing = byLayer.get(layer);
    if (existing) return existing;
    const d = DEFAULT_POLICY[layer];
    return {
      id: null,
      tenantId,
      layer,
      retentionValue: d.retentionValue,
      retentionUnit: d.retentionUnit,
      legalBasis: d.legalBasis,
      exceptionNote: d.exceptionNote,
      statutoryMinDays: d.statutoryMinDays,
      statutoryBasis: '',
      version: 0,
      effectiveFrom: null,
      updatedAt: null,
      isDefault: true,
    };
  });
}

export function mapPolicy(r) {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    layer: r.layer,
    retentionValue: r.retention_value,
    retentionUnit: r.retention_unit,
    legalBasis: r.legal_basis,
    exceptionNote: r.exception_note,
    statutoryMinDays: r.statutory_min_days,
    statutoryBasis: r.statutory_basis,
    version: r.version,
    effectiveFrom: r.effective_from,
    updatedAt: r.updated_at,
    isDefault: false,
  };
}

export function getPolicyForLayer(db, tenantId, layer) {
  return getPolicies(db, tenantId).find((p) => p.layer === layer);
}

// --- legal holds --------------------------------------------------------------

export function activeHolds(db, tenantId, nowMs = clock.now()) {
  return db
    .prepare(
      `SELECT * FROM legal_holds
        WHERE tenant_id = ? AND status = 'active'
          AND (expires_at IS NULL OR expires_at > ?)
        ORDER BY placed_at DESC`
    )
    .all(tenantId, nowMs)
    .map(mapHold);
}

export function mapHold(r) {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    scopeKind: r.scope_kind,
    subjectToken: r.subject_token,
    subjectLabel: r.subject_label,
    layer: r.layer,
    fromMs: r.from_ms,
    toMs: r.to_ms,
    reason: r.reason,
    legalBasis: r.legal_basis,
    status: r.status,
    placedAt: r.placed_at,
    placedBy: r.placed_by,
    expiresAt: r.expires_at,
    releasedAt: r.released_at,
    releasedBy: r.released_by,
  };
}

/**
 * Returns the first active hold whose scope covers this object, or null.
 * Scope semantics:
 *   tenant     -> everything for the tenant
 *   subject    -> objects carrying that subject token
 *   date_range -> objects whose effective time falls inside [from, to]
 * A hold may additionally be narrowed to a single layer.
 */
export function holdCovers(hold, { layer, subjectToken, timeMs }) {
  if (hold.layer && hold.layer !== layer) return false;
  switch (hold.scopeKind) {
    case 'tenant':
      return true;
    case 'subject':
      return Boolean(subjectToken) && hold.subjectToken === subjectToken;
    case 'date_range':
      return typeof timeMs === 'number' && timeMs >= hold.fromMs && timeMs <= hold.toMs;
    default:
      return false;
  }
}

export function findCoveringHold(holds, object) {
  for (const hold of holds) {
    if (holdCovers(hold, object)) return hold;
  }
  return null;
}

/**
 * Statutory retention exception: a legal minimum that survives an erasure
 * request. Unlike a hold, this is a property of the layer's policy, not an
 * ad-hoc case. Objects younger than the floor must be kept even on request.
 */
export function statutoryBlock(policy, timeMs, nowMs = clock.now()) {
  const floor = statutoryMs(policy);
  if (!floor) return null;
  const age = nowMs - timeMs;
  if (age >= floor) return null;
  return {
    reason: 'statutory_minimum',
    basis: policy.statutoryBasis || policy.legalBasis,
    retainUntilMs: timeMs + floor,
    policyVersion: policy.version,
  };
}

/**
 * Resolve why one object may not be erased, or null when it is clear.
 * Order matters: an explicit legal hold outranks a statutory floor because
 * both are blocking, but the hold is the more specific evidence.
 */
export function resolveBlocker({ holds, policy, layer, subjectToken, timeMs, nowMs = clock.now(), enforceStatutory = true }) {
  const hold = findCoveringHold(holds, { layer, subjectToken, timeMs });
  if (hold) {
    return {
      reason: hold.scopeKind === 'subject' ? 'legal_hold_subject' : hold.scopeKind === 'date_range' ? 'legal_hold_range' : 'legal_hold_tenant',
      ref: hold.id,
      detail: hold.reason,
      basis: hold.legalBasis,
      retainUntilMs: hold.expiresAt ?? null,
    };
  }
  if (enforceStatutory) {
    const stat = statutoryBlock(policy, timeMs, nowMs);
    if (stat) return { ref: null, detail: 'Statutory retention floor', ...stat };
  }
  return null;
}

// --- scope scanning -----------------------------------------------------------

export function timeColumn(layer) {
  return TIME_COLUMN[layer];
}

export function subjectColumn(layer) {
  return SUBJECT_COLUMN[layer];
}

/**
 * List objects in a layer for a retention sweep (time <= cutoff) or for a
 * subject erasure (subject token match, optional time bound).
 * Only opaque columns leave this function; payloads stay in the caller's row.
 */
export function scanLayer(db, tenantId, layer, { cutoffMs = null, subjectToken = null, limit = null } = {}) {
  const table = TABLE_BY_LAYER[layer];
  const timeCol = TIME_COLUMN[layer];
  const subjCol = SUBJECT_COLUMN[layer];
  const where = ['tenant_id = ?'];
  const params = [tenantId];
  if (cutoffMs !== null) {
    where.push(`${timeCol} <= ?`);
    params.push(cutoffMs);
  }
  if (subjectToken !== null) {
    where.push(`${subjCol} = ?`);
    params.push(subjectToken);
  }
  let sql = `SELECT * FROM ${table} WHERE ${where.join(' AND ')} ORDER BY ${timeCol} ASC, id ASC`;
  if (limit !== null) {
    sql += ' LIMIT ?';
    params.push(limit);
  }
  return db.prepare(sql).all(...params).map((row) => ({
    layer,
    objectRef: `${layer}:${row.id}`,
    id: row.id,
    timeMs: row[timeCol],
    subjectToken: row[subjCol] ?? null,
    generation: row.generation ?? 1,
    row,
  }));
}

export function countLayer(db, tenantId, layer, { cutoffMs = null, subjectToken = null } = {}) {
  const table = TABLE_BY_LAYER[layer];
  const timeCol = TIME_COLUMN[layer];
  const subjCol = SUBJECT_COLUMN[layer];
  const where = ['tenant_id = ?'];
  const params = [tenantId];
  if (cutoffMs !== null) { where.push(`${timeCol} <= ?`); params.push(cutoffMs); }
  if (subjectToken !== null) { where.push(`${subjCol} = ?`); params.push(subjectToken); }
  return db.prepare(`SELECT COUNT(*) AS c FROM ${table} WHERE ${where.join(' AND ')}`).get(...params).c;
}

/**
 * Live view of what is pending for a tenant: objects already past each
 * layer's retention cut-off, split into clear and blocked.
 */
export function pendingByLayer(db, tenantId, nowMs = clock.now()) {
  const policies = getPolicies(db, tenantId);
  const holds = activeHolds(db, tenantId, nowMs);
  return LAYERS.map((layer) => {
    const policy = policies.find((p) => p.layer === layer);
    const cutoffMs = cutoffFor(policy, nowMs);
    const objects = scanLayer(db, tenantId, layer, { cutoffMs });
    const blocked = [];
    let clear = 0;
    for (const obj of objects) {
      const blocker = resolveBlocker({
        holds, policy, layer, subjectToken: obj.subjectToken, timeMs: obj.timeMs, nowMs,
        enforceStatutory: false,
      });
      if (blocker) blocked.push({ objectRef: obj.objectRef, timeMs: obj.timeMs, blocker });
      else clear += 1;
    }
    return {
      layer,
      label: LAYER_LABELS[layer],
      policy,
      cutoffMs,
      retentionMs: retentionMs(policy),
      totalObjects: countLayer(db, tenantId, layer),
      sweepEligible: clear,
      blockedCount: blocked.length,
      blocked: blocked.slice(0, 50),
      oldestMs: objects.length ? objects[0].timeMs : null,
      newestEligibleMs: objects.length ? objects[objects.length - 1].timeMs : null,
    };
  });
}

/** Blockers that apply to an erasure request for one subject, by layer. */
export function subjectBlockers(db, tenantId, subjectToken, nowMs = clock.now()) {
  const policies = getPolicies(db, tenantId);
  const holds = activeHolds(db, tenantId, nowMs);
  return LAYERS.map((layer) => {
    const policy = policies.find((p) => p.layer === layer);
    const objects = scanLayer(db, tenantId, layer, { subjectToken });
    const blocked = [];
    let clear = 0;
    for (const obj of objects) {
      const blocker = resolveBlocker({
        holds, policy, layer, subjectToken: obj.subjectToken, timeMs: obj.timeMs, nowMs,
      });
      if (blocker) blocked.push({ objectRef: obj.objectRef, timeMs: obj.timeMs, blocker });
      else clear += 1;
    }
    return { layer, policy, clearCount: clear, blockedCount: blocked.length, blocked, objects };
  });
}
