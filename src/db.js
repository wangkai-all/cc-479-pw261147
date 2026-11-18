import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const WAREHOUSE_TABLES = {
  raw: 'raw_events',
  detail: 'detail_records',
  summary: 'summary_rollups',
  cache: 'cache_entries',
};

export const LAYERS = Object.keys(WAREHOUSE_TABLES);
export const TABLE_BY_LAYER = WAREHOUSE_TABLES;

/**
 * Fence triggers are the durable backstop for "deleted data must not come
 * back". Each warehouse table gets a BEFORE INSERT and BEFORE UPDATE trigger
 * that consults `fences` and aborts when the incoming row lands inside a
 * cleared range. Enforcement lives in the database, not in application code,
 * so a misbehaving or out-of-band writer still cannot re-enter a range.
 *
 * The trigger body uses `(select count(*) ...) > 0` rather than EXISTS
 * because SQLite rejects some subquery forms in a trigger WHEN clause.
 */
const TIME_COLUMN = {
  raw_events: 'occurred_at',
  detail_records: 'occurred_at',
  summary_rollups: 'computed_at',
  cache_entries: 'created_at',
};

function fenceTriggerSql(layer, table, op) {
  const timeCol = TIME_COLUMN[table];
  return `
CREATE TRIGGER IF NOT EXISTS trg_fence_${table}_${op}
BEFORE ${op.toUpperCase()} ON ${table}
FOR EACH ROW
WHEN (SELECT COUNT(*) FROM fences f
      WHERE f.tenant_id = NEW.tenant_id
        AND f.layer = '${layer}'
        AND (
          (f.kind = 'watermark' AND NEW.${timeCol} <= f.cutoff_ms)
          OR
          (f.kind = 'subject'
             AND NEW.subject_token IS NOT NULL
             AND NEW.subject_token = f.subject_token
             AND COALESCE(NEW.generation, 1) <= f.max_generation)
        )) > 0
BEGIN
  SELECT RAISE(ABORT, 'FENCED_RANGE: write touches a cleared retention range');
END;
`;
}

function timeExpr(table) {
  return `${table}.${TIME_COLUMN[table]}`;
}

export function openDatabase(dbPath) {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  }
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec('PRAGMA synchronous = NORMAL;');
  return db;
}

export function migrate(db) {
  const schema = fs.readFileSync(path.join(import.meta.dirname, 'schema.sql'), 'utf8');
  db.exec(schema);
  // Drop and recreate fence triggers so schema changes to the tables above
  // never leave a stale trigger behind.
  for (const [layer, table] of Object.entries(WAREHOUSE_TABLES)) {
    db.exec(`DROP TRIGGER IF EXISTS trg_fence_${table}_insert`);
    db.exec(`DROP TRIGGER IF EXISTS trg_fence_${table}_update`);
    db.exec(fenceTriggerSql(layer, table, 'insert'));
    db.exec(fenceTriggerSql(layer, table, 'update'));
  }
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
    BEFORE UPDATE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
    BEFORE DELETE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
  `);
  return db;
}

// --- small transaction helper -------------------------------------------------
export function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch { /* already rolled back */ }
    throw err;
  }
}

export function uuid(prefix = '') {
  const id = crypto.randomUUID();
  return prefix ? `${prefix}_${id}` : id;
}

export function nowIso(ms) {
  return new Date(ms).toISOString();
}

export { timeExpr };
