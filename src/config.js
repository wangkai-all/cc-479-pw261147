import path from 'node:path';
import fs from 'node:fs';

const root = path.resolve(import.meta.dirname, '..');

function intEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n)) throw new Error(`${name} must be an integer`);
  return n;
}

export const config = {
  root,
  port: intEnv('PORT', 4319),
  host: process.env.HOST || '127.0.0.1',
  dbPath: process.env.DB_PATH || path.join(root, 'data', 'retention.db'),
  publicDir: path.join(root, 'public'),
  // Deterministic clock for tests/demo: frozen ISO timestamp or offset.
  nowMs: () => clock.now(),
  seedOnStart: process.env.SEED_ON_START !== '0',
  // Where the seeded proof key lives; never exposed over HTTP.
  masterSecret: process.env.MASTER_SECRET || 'dev-master-secret-do-not-use-in-prod',
};

// Central clock so tests can freeze time without monkeypatching Date.
export const clock = {
  frozenAt: null,
  offsetMs: 0,
  now() {
    if (this.frozenAt !== null) return this.frozenAt;
    return Date.now() + this.offsetMs;
  },
  freeze(ms) { this.frozenAt = ms; return this; },
  unfreeze() { this.frozenAt = null; return this; },
  advance(ms) { this.offsetMs += ms; return this; },
};

export function ensureDirs() {
  fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
}
