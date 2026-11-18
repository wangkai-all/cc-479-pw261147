import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { config, clock } from './config.js';
import { LAYERS, openDatabase, migrate } from './db.js';
import { HttpError } from './erasure.js';
import {
  getTenant,
  holdsView,
  ingestEvents,
  listTenants,
  placeHold,
  policiesView,
  recentRejections,
  releaseHold,
  renewConsent,
  tenantOverview,
  tokenFor,
  updatePolicy,
  resetPolicy,
  auditTrail,
} from './services.js';
import {
  createRetentionSweep,
  createSubjectErasure,
  executeRequest,
  inspectRetentionSweep,
  inspectSubjectErasure,
  verifyProof,
} from './erasure.js';
import { getRequest, listRequests, getProof } from './requests.js';
import { ensureDirs } from './config.js';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(data),
  });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 2 * 1024 * 1024) {
        reject(new HttpError(413, 'payload_too_large', 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'invalid_json', 'request body must be valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

/** Actor identity is a header in this demo, not authenticated identity. */
function actorOf(req) {
  const actor = req.headers['x-actor'];
  if (Array.isArray(actor)) return actor[0];
  return actor && String(actor).trim() ? String(actor).trim() : 'operator@console';
}

export function createApp({ db }) {
  const now = () => clock.now();

  const routes = [];
  const route = (method, pattern, handler) => routes.push({ method, pattern, handler });

  const tenantFrom = (params) => {
    if (!params.tenantId) throw new HttpError(400, 'missing_tenant', 'tenantId is required');
    return params.tenantId;
  };

  // ---- meta ----
  route('GET', /^\/api\/health$/, () => ({ ok: true, nowMs: now(), time: new Date(now()).toISOString() }));

  route('GET', /^\/api\/tenants$/, () => ({ tenants: listTenants(db) }));

  route('GET', /^\/api\/tenants\/([^/]+)$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    return { tenant: getTenant(db, tenantId) };
  });

  route('GET', /^\/api\/tenants\/([^/]+)\/overview$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    return tenantOverview(db, tenantId, now());
  });

  // ---- policies ----
  route('GET', /^\/api\/tenants\/([^/]+)\/policies$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    return { policies: policiesView(db, tenantId, now()) };
  });

  route('PATCH', /^\/api\/tenants\/([^/]+)\/policies\/([^/]+)$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    const layer = m[2];
    const policy = updatePolicy(db, tenantId, layer, ctx.body || {}, { actor: ctx.actor, nowMs: now() });
    return { policy };
  });

  route('POST', /^\/api\/tenants\/([^/]+)\/policies\/([^/]+)\/reset$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    const policy = resetPolicy(db, tenantId, m[2], { actor: ctx.actor, nowMs: now() });
    return { policy };
  });

  // ---- holds ----
  route('GET', /^\/api\/tenants\/([^/]+)\/holds$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    return { holds: holdsView(db, tenantId, now()) };
  });

  route('POST', /^\/api\/tenants\/([^/]+)\/holds$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    return { hold: placeHold(db, tenantId, ctx.body || {}, { actor: ctx.actor, nowMs: now() }) };
  });

  route('POST', /^\/api\/tenants\/([^/]+)\/holds\/([^/]+)\/release$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    return { hold: releaseHold(db, tenantId, m[2], { actor: ctx.actor, nowMs: now() }) };
  });

  // ---- dry-run inspection ----
  route('GET', /^\/api\/tenants\/([^/]+)\/pending$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    return inspectRetentionSweep(db, tenantId, { nowMs: now() });
  });

  route('POST', /^\/api\/tenants\/([^/]+)\/subjects\/inspect$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    const subjectRef = ctx.body?.subjectRef;
    if (!subjectRef) throw new HttpError(400, 'missing_subject', 'subjectRef is required');
    return inspectSubjectErasure(db, tenantId, subjectRef, { nowMs: now() });
  });

  // ---- erasure requests ----
  route('GET', /^\/api\/tenants\/([^/]+)\/requests$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    return { requests: listRequests(db, tenantId) };
  });

  route('POST', /^\/api\/tenants\/([^/]+)\/requests$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    const body = ctx.body || {};
    if (body.kind === 'retention_sweep') {
      const layers = normalizeLayers(body.layers);
      const created = createRetentionSweep(db, tenantId, { actor: ctx.actor, nowMs: now(), layers });
      if (body.execute !== false) {
        const run = executeRequest(db, created.requestId, {
          actor: ctx.actor, nowMs: now(), batchSize: 100,
        });
        return { ...created, execution: run };
      }
      return created;
    }
    if (body.kind === 'subject_erasure') {
      if (!body.subjectRef) throw new HttpError(400, 'missing_subject', 'subjectRef is required');
      const layers = normalizeLayers(body.layers);
      const created = createSubjectErasure(db, tenantId, {
        actor: ctx.actor, nowMs: now(), subjectRef: body.subjectRef, layers,
      });
      if (body.execute !== false) {
        const run = executeRequest(db, created.requestId, {
          actor: ctx.actor, nowMs: now(), batchSize: 100,
        });
        return { ...created, execution: run };
      }
      return created;
    }
    throw new HttpError(400, 'invalid_kind', 'kind must be retention_sweep or subject_erasure');
  });

  route('GET', /^\/api\/tenants\/([^/]+)\/requests\/([^/]+)$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    return getRequest(db, tenantId, m[2]);
  });

  route('POST', /^\/api\/tenants\/([^/]+)\/requests\/([^/]+)\/execute$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getRequest(db, tenantId, m[2]);
    return { execution: executeRequest(db, m[2], { actor: ctx.actor, nowMs: now(), batchSize: 100 }) };
  });

  route('GET', /^\/api\/tenants\/([^/]+)\/requests\/([^/]+)\/manifest$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    const detail = getRequest(db, tenantId, m[2]);
    const row = db.prepare('SELECT * FROM erase_manifests WHERE id = ?').get(detail.request.manifestId);
    return { manifest: JSON.parse(row.payload_json), hash: row.manifest_hash };
  });

  route('GET', /^\/api\/tenants\/([^/]+)\/requests\/([^/]+)\/proof$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    return { proof: getProof(db, tenantId, m[2]) };
  });

  route('POST', /^\/api\/tenants\/([^/]+)\/requests\/([^/]+)\/verify$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getRequest(db, tenantId, m[2]);
    return { verification: verifyProof(db, m[2], { actor: ctx.actor, nowMs: now() }) };
  });

  // ---- ingestion & rejection feed ----
  route('POST', /^\/api\/tenants\/([^/]+)\/ingest$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    const body = ctx.body || {};
    return ingestEvents(db, tenantId, body.events, { actor: ctx.actor, nowMs: now() });
  });

  route('GET', /^\/api\/tenants\/([^/]+)\/rejections$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    return { rejections: recentRejections(db, tenantId, 50) };
  });

  // ---- consent ----
  route('POST', /^\/api\/tenants\/([^/]+)\/consent$/, (m, ctx) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    return { consent: renewConsent(db, tenantId, ctx.body || {}, { actor: ctx.actor, nowMs: now() }) };
  });

  route('GET', /^\/api\/tenants\/([^/]+)\/token$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    const ref = m.query.get('subjectRef');
    if (!ref) throw new HttpError(400, 'missing_subject', 'subjectRef query param is required');
    return { subjectToken: tokenFor(db, tenantId, ref) };
  });

  // ---- audit ----
  route('GET', /^\/api\/tenants\/([^/]+)\/audit$/, (m) => {
    const tenantId = tenantFrom({ tenantId: m[1] });
    getTenant(db, tenantId);
    const requestId = m.query.get('requestId');
    return { events: auditTrail(db, tenantId, { limit: 300, requestId }) };
  });

  // ---- static ----
  function serveStatic(req, res, pathname) {
    const rel = pathname === '/' ? '/index.html' : pathname;
    const filePath = path.normalize(path.join(config.publicDir, rel));
    if (!filePath.startsWith(config.publicDir)) {
      json(res, 403, { error: { code: 'forbidden', message: 'invalid path' } });
      return true;
    }
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return false;
    const ext = path.extname(filePath);
    res.writeHead(200, {
      'content-type': MIME[ext] || 'application/octet-stream',
      'cache-control': 'no-cache',
    });
    fs.createReadStream(filePath).pipe(res);
    return true;
  }

  return async function handle(req, res) {
    try {
      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const pathname = decodeURIComponent(url.pathname);

      if (!pathname.startsWith('/api/')) {
        if (serveStatic(req, res, pathname)) return;
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('not found');
        return;
      }

      const match = routes.find((r) => r.method === req.method && r.pattern.test(pathname));
      if (!match) {
        json(res, 404, { error: { code: 'not_found', message: `no route for ${req.method} ${pathname}` } });
        return;
      }
      const m = match.pattern.exec(pathname) || [];
      m.query = url.searchParams;
      const body = ['POST', 'PATCH', 'PUT'].includes(req.method) ? await readBody(req) : {};
      const ctx = { body, actor: actorOf(req), query: url.searchParams };
      const result = await match.handler(m, ctx);
      json(res, 200, result);
    } catch (err) {
      if (err instanceof HttpError) {
        json(res, err.status, { error: { code: err.code, message: err.message, details: err.details } });
        return;
      }
      console.error(err);
      json(res, 500, { error: { code: 'internal_error', message: 'internal server error' } });
    }
  };
}

function normalizeLayers(layers) {
  if (layers === undefined || layers === null) return LAYERS;
  if (!Array.isArray(layers) || layers.length === 0) {
    throw new HttpError(400, 'invalid_layers', 'layers must be a non-empty array');
  }
  // Preserve canonical order regardless of input order for reproducible manifests.
  return LAYERS.filter((l) => layers.includes(l));
}

export function createServer({ dbPath = config.dbPath } = {}) {
  ensureDirs();
  const db = migrate(openDatabase(dbPath));
  const app = createApp({ db });
  const server = http.createServer(app);
  return { server, db };
}

// Direct invocation
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const { server, db } = createServer();
  // First run against an empty database: seed demo tenants so the console is
  // usable immediately. Existing data is never touched.
  if (config.seedOnStart) {
    const empty = db.prepare('SELECT COUNT(*) c FROM tenants').get().c === 0;
    if (empty) {
      const { seed } = await import('../scripts/seed.js');
      seed(db, { nowMs: clock.now() });
      console.log('Seeded demo tenants (set SEED_ON_START=0 to disable).');
    }
  }
  server.listen(config.port, config.host, () => {
    console.log(`Retention console on http://${config.host}:${config.port}`);
  });
}
