import { LAYERS, tx, uuid } from './db.js';
import {
  keyFingerprint,
  subjectToken as makeSubjectToken,
} from './crypto.js';
import {
  DEFAULT_POLICY,
  LAYER_LABELS,
  activeHolds,
  getPolicies,
  getPolicyForLayer,
  mapHold,
  pendingByLayer,
  retentionMs,
  statutoryMs,
} from './policy.js';
import { appendAudit, listAudit, verifyAuditChain } from './audit.js';
import { HttpError } from './erasure.js';

const HOUR = 3_600_000;
const DAY = 86_400_000;

export function listTenants(db) {
  return db.prepare('SELECT * FROM tenants ORDER BY name').all().map((t) => ({
    id: t.id, name: t.name, region: t.region, description: t.description, createdAt: t.created_at,
  }));
}

export function getTenant(db, tenantId) {
  const t = db.prepare('SELECT * FROM tenants WHERE id = ?').get(tenantId);
  if (!t) throw new HttpError(404, 'tenant_not_found', 'no such tenant');
  return { id: t.id, name: t.name, region: t.region, description: t.description, createdAt: t.created_at };
}

function tenantKey(db, tenantId) {
  const row = db.prepare('SELECT * FROM tenant_keys WHERE tenant_id = ?').get(tenantId);
  if (!row) throw new HttpError(500, 'missing_tenant_key', 'tenant key not provisioned');
  return row;
}

export function tokenFor(db, tenantId, subjectRef) {
  return makeSubjectToken(tenantKey(db, tenantId).proof_key, subjectRef);
}

// --- policy ------------------------------------------------------------------

function policyView(p) {
  return {
    ...p,
    retentionMs: retentionMs(p),
    statutoryMs: statutoryMs(p),
    label: LAYER_LABELS[p.layer],
  };
}

export function policiesView(db, tenantId, nowMs) {
  return getPolicies(db, tenantId).map((p) => ({
    ...policyView(p),
    cutoffMs: nowMs - retentionMs(p),
    nextSweepEligibleMs: null,
  }));
}

/**
 * Policy updates are append-only versions. Validation enforces the core
 * safety invariant: the normal retention window can never be shorter than the
 * statutory minimum, otherwise a routine sweep could delete legally protected
 * records.
 */
export function updatePolicy(db, tenantId, layer, patch, { actor, nowMs }) {
  if (!LAYERS.includes(layer)) throw new HttpError(400, 'unknown_layer', `unknown layer ${layer}`);
  const current = getPolicies(db, tenantId).find((p) => p.layer === layer);
  if (!current) throw new HttpError(404, 'policy_not_found', 'no policy for layer');

  const retentionValue = patch.retentionValue ?? current.retentionValue;
  const retentionUnit = patch.retentionUnit ?? current.retentionUnit;
  if (!Number.isInteger(retentionValue) || retentionValue <= 0) {
    throw new HttpError(400, 'invalid_retention', 'retentionValue must be a positive integer');
  }
  if (!['hours', 'days'].includes(retentionUnit)) {
    throw new HttpError(400, 'invalid_retention_unit', 'retentionUnit must be hours or days');
  }
  const statutoryMinDays = patch.statutoryMinDays ?? current.statutoryMinDays;
  if (!Number.isInteger(statutoryMinDays) || statutoryMinDays < 0) {
    throw new HttpError(400, 'invalid_statutory', 'statutoryMinDays must be a non-negative integer');
  }
  const next = {
    retentionValue,
    retentionUnit,
    statutoryMinDays,
    legalBasis: patch.legalBasis ?? current.legalBasis,
    statutoryBasis: patch.statutoryBasis ?? current.statutoryBasis,
    exceptionNote: patch.exceptionNote ?? current.exceptionNote,
  };
  if (!next.legalBasis || typeof next.legalBasis !== 'string') {
    throw new HttpError(400, 'invalid_legal_basis', 'legalBasis is required');
  }
  const retention = retentionValue * (retentionUnit === 'hours' ? HOUR : DAY);
  const statutory = statutoryMinDays * DAY;
  if (retention < statutory) {
    throw new HttpError(400, 'retention_below_statutory',
      'retention window cannot be shorter than the statutory minimum');
  }

  return tx(db, () => {
    db.prepare('UPDATE retention_policies SET is_current = 0 WHERE tenant_id = ? AND layer = ?')
      .run(tenantId, layer);
    const version = (current.version ?? 0) + 1;
    const id = uuid('pol');
    db.prepare(
      `INSERT INTO retention_policies
        (id, tenant_id, layer, retention_value, retention_unit, legal_basis, exception_note,
         statutory_min_days, statutory_basis, version, is_current, effective_from, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
    ).run(
      id, tenantId, layer, next.retentionValue, next.retentionUnit, next.legalBasis,
      next.exceptionNote, next.statutoryMinDays, next.statutoryBasis || '',
      version, nowMs, nowMs
    );
    appendAudit(db, {
      tenantId, type: 'policy.updated', actor, at: nowMs,
      payload: {
        layer,
        version,
        previous: {
          retentionValue: current.retentionValue,
          retentionUnit: current.retentionUnit,
          statutoryMinDays: current.statutoryMinDays,
        },
        next: {
          retentionValue: next.retentionValue,
          retentionUnit: next.retentionUnit,
          statutoryMinDays: next.statutoryMinDays,
        },
      },
    });
    return policyView(getPolicyForLayer(db, tenantId, layer));
  });
}

/** Restore the built-in default for a layer as a new policy version. */
export function resetPolicy(db, tenantId, layer, { actor, nowMs }) {
  const d = DEFAULT_POLICY[layer];
  if (!d) throw new HttpError(400, 'unknown_layer', `unknown layer ${layer}`);
  return updatePolicy(db, tenantId, layer, { ...d, statutoryMinDays: d.statutoryMinDays }, { actor, nowMs });
}

// --- legal holds -------------------------------------------------------------

export function holdsView(db, tenantId, nowMs) {
  return db
    .prepare('SELECT * FROM legal_holds WHERE tenant_id = ? ORDER BY placed_at DESC')
    .all(tenantId)
    .map(mapHold)
    .map((h) => ({
      ...h,
      active: h.status === 'active' && (h.expiresAt === null || h.expiresAt > nowMs),
    }));
}

export function placeHold(db, tenantId, input, { actor, nowMs }) {
  const scopeKind = input.scopeKind;
  if (!['tenant', 'subject', 'date_range'].includes(scopeKind)) {
    throw new HttpError(400, 'invalid_scope', 'scopeKind must be tenant, subject or date_range');
  }
  if (input.layer && !LAYERS.includes(input.layer)) {
    throw new HttpError(400, 'unknown_layer', `unknown layer ${input.layer}`);
  }
  if (!input.reason || !String(input.reason).trim()) {
    throw new HttpError(400, 'missing_reason', 'a hold reason is required');
  }
  if (!input.legalBasis || !String(input.legalBasis).trim()) {
    throw new HttpError(400, 'missing_legal_basis', 'a legal basis is required');
  }

  let subjectToken = null;
  let subjectLabel = null;
  if (scopeKind === 'subject') {
    if (!input.subjectRef && !input.subjectToken) {
      throw new HttpError(400, 'missing_subject', 'subject scope requires subjectRef');
    }
    subjectToken = input.subjectToken || tokenFor(db, tenantId, input.subjectRef);
    subjectLabel = input.subjectLabel || maskSubjectRef(input.subjectRef || '') || null;
  }
  let fromMs = null;
  let toMs = null;
  if (scopeKind === 'date_range') {
    fromMs = Number(input.fromMs);
    toMs = Number(input.toMs);
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || fromMs > toMs) {
      throw new HttpError(400, 'invalid_range', 'date_range requires fromMs <= toMs');
    }
  }
  const expiresAt = input.expiresAt == null ? null : Number(input.expiresAt);
  if (expiresAt !== null && (!Number.isFinite(expiresAt) || expiresAt <= nowMs)) {
    throw new HttpError(400, 'invalid_expiry', 'expiresAt must be in the future');
  }

  const id = uuid('hold');
  return tx(db, () => {
    db.prepare(
      `INSERT INTO legal_holds
        (id, tenant_id, scope_kind, subject_token, subject_label, layer, from_ms, to_ms,
         reason, legal_basis, status, placed_at, placed_by, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`
    ).run(
      id, tenantId, scopeKind, subjectToken, subjectLabel, input.layer || null,
      fromMs, toMs, String(input.reason).trim(), String(input.legalBasis).trim(),
      nowMs, actor, expiresAt
    );
    appendAudit(db, {
      tenantId, type: 'hold.placed', actor, at: nowMs,
      payload: {
        holdId: id, scopeKind, layer: input.layer || null,
        subjectToken, fromMs, toMs, expiresAt, legalBasis: input.legalBasis,
      },
    });
    return mapHold(db.prepare('SELECT * FROM legal_holds WHERE id = ?').get(id));
  });
}

export function releaseHold(db, tenantId, holdId, { actor, nowMs }) {
  const row = db.prepare('SELECT * FROM legal_holds WHERE id = ? AND tenant_id = ?').get(holdId, tenantId);
  if (!row) throw new HttpError(404, 'hold_not_found', 'no such hold');
  if (row.status !== 'active') {
    throw new HttpError(409, 'hold_not_active', `hold is already ${row.status}`);
  }
  return tx(db, () => {
    db.prepare("UPDATE legal_holds SET status = 'released', released_at = ?, released_by = ? WHERE id = ?")
      .run(nowMs, actor, holdId);
    appendAudit(db, {
      tenantId, type: 'hold.released', actor, at: nowMs,
      payload: { holdId, scopeKind: row.scope_kind, layer: row.layer },
    });
    return mapHold(db.prepare('SELECT * FROM legal_holds WHERE id = ?').get(holdId));
  });
}

/** Only enough of the identifier to let an operator recognise it. */
function maskSubjectRef(ref) {
  const s = String(ref);
  if (!s) return null;
  if (s.length <= 4) return '•'.repeat(s.length);
  return s.slice(0, 2) + '•'.repeat(Math.max(2, s.length - 4)) + s.slice(-2);
}

// --- consent / generation ----------------------------------------------------

export function consentFor(db, tenantId, subjectToken) {
  const row = db.prepare('SELECT * FROM subject_consents WHERE tenant_id = ? AND subject_token = ?')
    .get(tenantId, subjectToken);
  return row ? { generation: row.generation, consentRef: row.consent_ref, updatedAt: row.updated_at } : null;
}

/**
 * Re-onboarding after an erasure. Raising the generation lifts the subject
 * fence (which only blocks writes at or below the erased generation) while
 * leaving the erasure proof and its history intact.
 */
export function renewConsent(db, tenantId, { subjectRef, consentRef }, { actor, nowMs }) {
  if (!subjectRef) throw new HttpError(400, 'missing_subject', 'subjectRef is required');
  if (!consentRef) throw new HttpError(400, 'missing_consent_ref', 'consentRef is required');
  const token = tokenFor(db, tenantId, subjectRef);
  return tx(db, () => {
    const existing = consentFor(db, tenantId, token);
    const generation = (existing?.generation ?? 1) + 1;
    db.prepare(
      `INSERT INTO subject_consents (tenant_id, subject_token, generation, consent_ref, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (tenant_id, subject_token)
       DO UPDATE SET generation = excluded.generation,
                     consent_ref = excluded.consent_ref,
                     updated_at = excluded.updated_at`
    ).run(tenantId, token, generation, consentRef, nowMs);
    appendAudit(db, {
      tenantId, type: 'consent.renewed', actor, at: nowMs,
      payload: { subjectToken: token, generation, consentRef },
    });
    return { subjectToken: token, generation, consentRef };
  });
}

export function currentGeneration(db, tenantId, subjectToken) {
  return consentFor(db, tenantId, subjectToken)?.generation ?? 1;
}

// --- ingestion ---------------------------------------------------------------

/**
 * Ingest events. Every write goes through the fence triggers; a rejected
 * write is recorded as a rejection (opaque token only) and reported back, so
 * an operator can see that a late batch was refused rather than silently
 * reintroducing cleared data.
 */
export function ingestEvents(db, tenantId, events, { actor, nowMs }) {
  if (!Array.isArray(events) || events.length === 0) {
    throw new HttpError(400, 'empty_batch', 'events must be a non-empty array');
  }
  if (events.length > 1000) {
    throw new HttpError(400, 'batch_too_large', 'at most 1000 events per batch');
  }
  const key = tenantKey(db, tenantId);
  const accepted = [];
  const rejected = [];

  tx(db, () => {
    for (const [i, ev] of events.entries()) {
      if (!ev || !ev.subjectRef || !ev.eventType) {
        throw new HttpError(400, 'invalid_event', `event ${i} requires subjectRef and eventType`);
      }
      const token = makeSubjectToken(key.proof_key, ev.subjectRef);
      const generation = Number.isInteger(ev.generation)
        ? ev.generation
        : currentGeneration(db, tenantId, token);
      const occurredAt = Number.isFinite(Number(ev.occurredAt)) ? Number(ev.occurredAt) : nowMs;
      const payload = JSON.stringify(ev.payload ?? {});
      try {
        const info = db.prepare(
          `INSERT INTO raw_events
            (tenant_id, subject_ref, subject_token, event_type, payload_json, occurred_at, ingested_at, source, generation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(tenantId, ev.subjectRef, token, ev.eventType, payload, occurredAt, nowMs, ev.source || 'collector', generation);
        accepted.push({ kind: 'raw', objectRef: `raw:${Number(info.lastInsertRowid)}` });
      } catch (err) {
        if (/FENCED_RANGE/.test(String(err.message))) {
          recordRejection(db, {
            tenantId, layer: 'raw', token, occurredAt, generation, reason: 'fence_watermark_or_subject', nowMs,
          });
          rejected.push({ layer: 'raw', subjectToken: token, occurredAt, reason: 'fenced_range' });
          continue;
        }
        throw err;
      }

      // Optional derived detail row for events that carry a transaction.
      if (ev.category) {
        try {
          const info = db.prepare(
            `INSERT INTO detail_records
              (tenant_id, subject_ref, subject_token, category, amount_cents, pii_json, occurred_at, generation)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(tenantId, ev.subjectRef, token, ev.category, Math.trunc(Number(ev.amountCents) || 0),
            JSON.stringify(ev.pii ?? {}), occurredAt, generation);
          accepted.push({ kind: 'detail', objectRef: `detail:${Number(info.lastInsertRowid)}` });
        } catch (err) {
          if (!/FENCED_RANGE/.test(String(err.message))) throw err;
          recordRejection(db, {
            tenantId, layer: 'detail', token, occurredAt, generation, reason: 'fence_watermark_or_subject', nowMs,
          });
          rejected.push({ layer: 'detail', subjectToken: token, occurredAt, reason: 'fenced_range' });
        }
      }
    }
    appendAudit(db, {
      tenantId, type: 'data.ingested', actor, at: nowMs,
      payload: { accepted: accepted.length, rejected: rejected.length },
    });
  });

  return { accepted: accepted.length, rejected: rejected.length, acceptedObjects: accepted, rejections: rejected };
}

function recordRejection(db, { tenantId, layer, token, occurredAt, generation, reason, nowMs }) {
  db.prepare(
    `INSERT INTO ingest_rejections
      (tenant_id, layer, subject_token, occurred_at, generation, reason, attempted_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(tenantId, layer, token, occurredAt, generation, reason, nowMs);
}

export function recentRejections(db, tenantId, limit = 20) {
  return db
    .prepare('SELECT * FROM ingest_rejections WHERE tenant_id = ? ORDER BY id DESC LIMIT ?')
    .all(tenantId, limit)
    .map((r) => ({
      id: r.id, layer: r.layer, subjectToken: r.subject_token,
      occurredAt: r.occurred_at, generation: r.generation, reason: r.reason, attemptedAt: r.attempted_at,
    }));
}

// --- overview ----------------------------------------------------------------

export function tenantOverview(db, tenantId, nowMs) {
  getTenant(db, tenantId);
  const pending = pendingByLayer(db, tenantId, nowMs);
  const requests = db
    .prepare(`SELECT * FROM erase_requests WHERE tenant_id = ? ORDER BY requested_at DESC, rowid DESC LIMIT 20`)
    .all(tenantId)
    .map(requestSummary);
  const holds = holdsView(db, tenantId, nowMs);
  const chain = verifyAuditChain(db, tenantId);

  const counts = db.prepare(
    `SELECT
       (SELECT COUNT(*) FROM raw_events WHERE tenant_id = ?) AS raw,
       (SELECT COUNT(*) FROM detail_records WHERE tenant_id = ?) AS detail,
       (SELECT COUNT(*) FROM summary_rollups WHERE tenant_id = ?) AS summary,
       (SELECT COUNT(*) FROM cache_entries WHERE tenant_id = ?) AS cache`
  ).get(tenantId, tenantId, tenantId, tenantId);

  return {
    tenant: getTenant(db, tenantId),
    keyFingerprint: keyFingerprint(tenantKey(db, tenantId).proof_key),
    policies: policiesView(db, tenantId, nowMs),
    pending,
    requests,
    holds,
    rejections: recentRejections(db, tenantId, 10),
    objectCounts: counts,
    audit: { valid: chain.valid, head: chain.head ?? null, checked: chain.checked },
    totals: {
      pendingEligible: pending.reduce((a, p) => a + p.sweepEligible, 0),
      pendingBlocked: pending.reduce((a, p) => a + p.blockedCount, 0),
      activeHolds: holds.filter((h) => h.active).length,
      openRequests: requests.filter((r) => ['awaiting_execution', 'running', 'blocked'].includes(r.status)).length,
    },
  };
}

export function requestSummary(r) {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    kind: r.kind,
    status: r.status,
    requestedBy: r.requested_by,
    requestedAt: r.requested_at,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    manifestId: r.manifest_id,
    manifestHash: r.manifest_hash,
    proofId: r.proof_id,
    itemTotal: r.item_total,
    itemErased: r.item_erased,
    itemBlocked: r.item_blocked,
    itemSkipped: r.item_skipped,
    error: r.error,
  };
}

export function auditTrail(db, tenantId, { limit = 200, requestId = null } = {}) {
  return listAudit(db, tenantId, { limit, requestId });
}
