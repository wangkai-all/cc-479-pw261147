// ---- API ------------------------------------------------------------------

const state = {
  tenantId: localStorage.getItem('tenantId') || null,
  tenants: [],
  overview: null,
  tab: 'overview',
  requests: [],
  requestDetail: null,
  proofView: null,
  policies: null,
  holds: null,
  audit: null,
  pending: null,
  busy: false,
  subjectInspect: null,
  policyEdit: null,
};

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-actor': actor(),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error?.message || `Request failed (${res.status})`;
    const err = new Error(msg);
    err.code = data?.error?.code;
    err.details = data?.error?.details;
    err.status = res.status;
    throw err;
  }
  return data;
}

function actor() {
  return localStorage.getItem('actor') || 'operator@console';
}

const T = (path, extra = '') => `/api/tenants/${encodeURIComponent(state.tenantId)}${path}${extra}`;

// ---- formatting -----------------------------------------------------------

const HOUR = 3_600_000;
const DAY = 86_400_000;

const fmtInt = new Intl.NumberFormat('en-US');
function n(x) { return fmtInt.format(x ?? 0); }
function compact(x) {
  if (x == null) return '—';
  if (x < 10_000) return fmtInt.format(x);
  if (x < 1e6) return (x / 1e3).toFixed(x < 1e5 ? 1 : 0) + 'K';
  return (x / 1e6).toFixed(1) + 'M';
}
function fmtDate(ms) {
  if (ms == null) return '—';
  return new Date(ms).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}
function fmtDay(ms) {
  if (ms == null) return '—';
  return new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
}
function relTime(ms) {
  if (ms == null) return '—';
  const diff = Date.now() - ms;
  const abs = Math.abs(diff);
  const unit = abs < HOUR ? 'min' : abs < DAY ? 'hour' : 'day';
  const val = unit === 'min' ? Math.round(abs / 60_000) : unit === 'hour' ? Math.round(abs / HOUR) : Math.round(abs / DAY);
  return diff >= 0 ? `${val} ${unit}${val === 1 ? '' : 's'} ago` : `in ${val} ${unit}${val === 1 ? '' : 's'}`;
}
function windowLabel(policy) {
  if (!policy) return '—';
  return `${policy.retentionValue} ${policy.retentionUnit}`;
}
function pct(a, b) { return b > 0 ? Math.round((a / b) * 100) : 0; }
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const LAYER_COLOR = { raw: 'var(--series-1)', detail: 'var(--series-2)', summary: 'var(--series-3)', cache: 'var(--series-4)' };
const LAYER_ORDER = ['raw', 'detail', 'summary', 'cache'];

// ---- render helpers -------------------------------------------------------

const app = document.getElementById('app');

function el(html) {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function badge(text, kind = 'neutral') {
  return `<span class="badge ${kind}"><span class="dot"></span>${esc(text)}</span>`;
}

function statusBadge(status) {
  const map = {
    awaiting_execution: ['Awaiting execution', 'info'],
    running: ['Running', 'info'],
    completed: ['Completed', 'good'],
    completed_with_exceptions: ['Completed with exceptions', 'warn'],
    blocked: ['Blocked', 'crit'],
    failed: ['Failed', 'crit'],
    cancelled: ['Cancelled', 'neutral'],
  };
  const [label, kind] = map[status] || [status, 'neutral'];
  return badge(label, kind);
}

function toast(message, isError = false) {
  const t = document.getElementById('toast');
  t.textContent = message;
  t.hidden = false;
  t.classList.toggle('error', isError);
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 4200);
}

function setLoading(v) {
  state.busy = v;
  document.body.style.cursor = v ? 'progress' : '';
}

async function run(fn, { success } = {}) {
  try {
    setLoading(true);
    const out = await fn();
    if (success) toast(success);
    return out;
  } catch (err) {
    toast(err.message, true);
    throw err;
  } finally {
    setLoading(false);
  }
}

// ---- data loading ---------------------------------------------------------

async function loadTenants() {
  const data = await api('GET', '/api/tenants');
  state.tenants = data.tenants;
  if (!state.tenantId || !state.tenants.some((t) => t.id === state.tenantId)) {
    state.tenantId = state.tenants[0]?.id ?? null;
  }
  if (state.tenantId) localStorage.setItem('tenantId', state.tenantId);
  renderTenantSelect();
}

function renderTenantSelect() {
  const sel = document.getElementById('tenant-select');
  sel.innerHTML = state.tenants
    .map((t) => `<option value="${esc(t.id)}" ${t.id === state.tenantId ? 'selected' : ''}>${esc(t.name)} · ${esc(t.region)}</option>`)
    .join('');
}

async function loadOverview() {
  state.overview = await api('GET', T('/overview'));
}

async function loadRequests() {
  const data = await api('GET', T('/requests'));
  state.requests = data.requests;
}

async function loadPolicies() {
  await loadOverview();
}

async function loadAudit() {
  const data = await api('GET', T('/audit'));
  state.audit = data.events;
}

async function loadPending() {
  state.pending = await api('GET', T('/pending'));
}

// ---- navigation -----------------------------------------------------------

function setTab(tab) {
  state.tab = tab;
  document.querySelectorAll('.tab').forEach((t) => {
    const on = t.dataset.tab === tab;
    t.classList.toggle('active', on);
    t.setAttribute('aria-selected', String(on));
  });
  render();
}

async function render() {
  try {
    setLoading(true);
    if (!state.tenantId) {
      app.innerHTML = '<div class="empty">No tenants configured. Run <code>npm run seed</code>.</div>';
      return;
    }
    if (state.tab === 'overview') await renderOverview();
    else if (state.tab === 'requests') await renderRequests();
    else if (state.tab === 'policies') await renderPoliciesView();
    else if (state.tab === 'audit') await renderAudit();
  } catch (err) {
    app.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  } finally {
    setLoading(false);
  }
}

window.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => setTab(t.dataset.tab)));
  document.getElementById('tenant-select').addEventListener('change', async (e) => {
    state.tenantId = e.target.value;
    localStorage.setItem('tenantId', state.tenantId);
    state.subjectInspect = null;
    await render();
  });
  initTheme();
  try {
    await loadTenants();
    await render();
  } catch (err) {
    app.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  }
});

function initTheme() {
  const saved = localStorage.getItem('theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = saved || (prefersDark ? 'dark' : 'light');
  document.documentElement.dataset.theme = theme;
  document.getElementById('theme-toggle').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('theme', next);
  });
}

// ---- tooltip --------------------------------------------------------------

const tip = document.getElementById('tooltip');
function showTip(evt, html) {
  tip.innerHTML = html;
  tip.hidden = false;
  const pad = 14;
  const x = Math.min(evt.clientX + pad, window.innerWidth - tip.offsetWidth - 8);
  const y = Math.max(evt.clientY - tip.offsetHeight - 10, 8);
  tip.style.left = `${x}px`;
  tip.style.top = `${y}px`;
}
function hideTip() { tip.hidden = true; }

// ===========================================================================
// Overview
// ===========================================================================

async function renderOverview() {
  await loadOverview();
  const o = state.overview;
  const t = o.tenant;

  app.innerHTML = `
    <div class="kpi-row">
      ${statTile('Eligible for sweep', compact(o.totals.pendingEligible), 'past retention · not held')}
      ${statTile('Blocked from deletion', compact(o.totals.pendingBlocked), 'held or statutorily protected')}
      ${statTile('Active legal holds', compact(o.totals.activeHolds), 'across all scopes')}
      ${statTile('Open requests', compact(o.totals.openRequests), 'awaiting execution or running')}
    </div>

    <div class="section">
      <div class="section-head">
        <h2>Retention by layer</h2>
        <span class="hint">${esc(t.name)} · ${esc(t.region)} · key ${esc(o.keyFingerprint)}</span>
      </div>
      <div class="card">
        <div class="card-pad" style="display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--grid)">
          <div class="legend">
            <span class="item"><span class="swatch" style="background:var(--series-1)"></span>Eligible for deletion</span>
            <span class="item"><span class="swatch" style="background:var(--serious)"></span>Blocked (held / statutory)</span>
            <span class="item"><span class="swatch" style="background:var(--grid)"></span>Within retention window</span>
          </div>
          <div class="row-actions">
            <button class="btn small" id="btn-inspect-subject">Inspect a subject</button>
            <button class="btn primary small" id="btn-run-sweep">Run retention sweep</button>
          </div>
        </div>
        <div id="layer-list"></div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-pad" style="padding-bottom:8px">
          <div class="flex-between">
            <h2 style="font-size:14px">Pending objects &amp; blocking reasons</h2>
            <span class="hint muted">${n(o.totals.pendingEligible)} clear · ${n(o.totals.pendingBlocked)} blocked</span>
          </div>
        </div>
        <div id="blockers-panel"></div>
      </div>
      <div class="card">
        <div class="card-pad" style="padding-bottom:8px">
          <h2 style="font-size:14px">Recent requests</h2>
        </div>
        <div id="recent-requests"></div>
      </div>
    </div>

    <div class="section" style="margin-top:24px">
      <div class="section-head">
        <h2>Ingestion fencing</h2>
        <span class="hint">Writes into a cleared range are rejected at the database</span>
      </div>
      <div class="card">
        <div id="rejections-panel"></div>
      </div>
    </div>
  `;

  renderLayerList(o.pending);
  renderBlockers(o.pending);
  renderRecentRequests(o.requests);
  renderRejections(o.rejections);

  document.getElementById('btn-run-sweep').addEventListener('click', () => openSweepDialog());
  document.getElementById('btn-inspect-subject').addEventListener('click', () => openInspectDialog());
}

function statTile(label, value, foot) {
  return `<div class="card stat">
    <div class="stat-label">${esc(label)}</div>
    <div class="stat-value">${value}</div>
    <div class="stat-foot">${esc(foot)}</div>
  </div>`;
}

/**
 * Each layer is one stacked bar: cleared-and-eligible, blocked, and retained.
 * Bars are on a shared scale (share of the layer's total), with the counts
 * printed beside the layer name so colour never carries a value alone.
 */
function renderLayerList(pending) {
  const host = document.getElementById('layer-list');
  if (!host) return;
  host.innerHTML = pending.map((p) => {
    const total = Math.max(1, p.totalObjects);
    const eligible = p.sweepEligible;
    const blocked = p.blockedCount;
    const keep = Math.max(0, p.totalObjects - eligible - blocked);
    const ePct = (eligible / total) * 100;
    const bPct = (blocked / total) * 100;
    const kPct = 100 - ePct - bPct;
    return `<div class="layer-row" data-layer="${esc(p.layer)}">
      <div class="layer-top">
        <div class="layer-name">
          <span class="layer-swatch" style="background:${LAYER_COLOR[p.layer]}"></span>
          ${esc(p.label)}
          <span class="layer-meta">retain ${esc(windowLabel(p.policy))}${p.policy.statutoryMinDays ? ` · statutory floor ${p.policy.statutoryMinDays}d` : ''}</span>
        </div>
        <div class="layer-meta num">
          <strong style="color:var(--text-primary)">${n(p.totalObjects)}</strong> objects ·
          ${n(eligible)} eligible · ${n(blocked)} blocked
        </div>
      </div>
      <div class="meter" role="img" aria-label="${esc(p.label)}: ${n(eligible)} eligible, ${n(blocked)} blocked, ${n(keep)} retained">
        ${ePct > 0 ? `<span class="seg erase" style="width:${ePct}%;flex:none" data-tip="${esc(p.label)}|${n(eligible)}|eligible for deletion"></span>` : ''}
        ${bPct > 0 ? `<span class="seg block" style="width:${bPct}%;flex:none" data-tip="${esc(p.label)}|${n(blocked)}|blocked by hold or statute"></span>` : ''}
        ${kPct > 0 ? `<span class="seg keep" style="width:${kPct}%;flex:none" data-tip="${esc(p.label)}|${n(keep)}|within retention window"></span>` : ''}
      </div>
      <div class="layer-meta" style="margin-top:6px">
        Cut-off ${fmtDate(p.cutoffMs)} · oldest pending ${p.oldestMs ? fmtDate(p.oldestMs) : '—'}
      </div>
    </div>`;
  }).join('');

  host.querySelectorAll('[data-tip]').forEach((seg) => {
    seg.addEventListener('pointermove', (e) => {
      const [layer, value, label] = seg.dataset.tip.split('|');
      showTip(e, `<div class="tt-label">${esc(layer)}</div><div class="tt-value">${value} <span class="tt-label">${esc(label)}</span></div>`);
    });
    seg.addEventListener('pointerleave', hideTip);
  });
}

/**
 * Blocker roll-up: group by reason so the operator sees "why" before object
 * refs. Object-level entries are one click away.
 */
function renderBlockers(pending) {
  const host = document.getElementById('blockers-panel');
  if (!host) return;
  const groups = new Map();
  for (const layer of pending) {
    for (const b of layer.blocked) {
      const key = b.blocker.ref ? `${b.blocker.reason}|${b.blocker.ref}` : b.blocker.reason;
      if (!groups.has(key)) {
        groups.set(key, {
          reason: b.blocker.reason, ref: b.blocker.ref, detail: b.blocker.detail,
          basis: b.blocker.basis, retainUntilMs: b.blocker.retainUntilMs,
          count: 0, layers: new Set(), samples: [],
        });
      }
      const g = groups.get(key);
      g.count += 1;
      g.layers.add(layer.layer);
      if (g.samples.length < 3) g.samples.push(b.objectRef);
    }
  }
  // Fold in the aggregate blocked count for any layer whose blocked list was
  // truncated by the API, so the totals still match the layer headers.
  const aggregate = pending.reduce((a, l) => a + l.blockedCount, 0);
  const listed = [...groups.values()].reduce((a, g) => a + g.count, 0);
  const unlisted = Math.max(0, aggregate - listed);

  if (groups.size === 0) {
    host.innerHTML = '<div class="empty">Nothing is blocked. Every pending object is eligible for deletion.</div>';
    return;
  }

  const reasonLabel = {
    legal_hold_subject: 'Legal hold — subject',
    legal_hold_tenant: 'Legal hold — tenant',
    legal_hold_range: 'Legal hold — date range',
    statutory_minimum: 'Statutory minimum retention',
  };

  host.innerHTML = `<div class="table-wrap"><table class="data">
    <thead><tr><th>Reason</th><th>Scope</th><th class="num">Objects</th><th>Retain until</th></tr></thead>
    <tbody>
      ${[...groups.values()].map((g) => `<tr>
        <td>
          <div style="font-weight:600">${esc(reasonLabel[g.reason] || g.reason)}</div>
          <div class="muted" style="font-size:11.5px">${esc(g.basis || g.detail || '')}</div>
        </td>
        <td>${[...g.layers].map((l) => badge(l, 'neutral')).join(' ')}</td>
        <td class="num" style="font-weight:600">${n(g.count)}
          <div class="muted" style="font-size:11px;font-weight:400">${g.samples.map(esc).join(', ')}${g.count > g.samples.length ? '…' : ''}</div>
        </td>
        <td class="secondary">${g.retainUntilMs ? fmtDay(g.retainUntilMs) : '<span class="muted">until released</span>'}</td>
      </tr>`).join('')}
    </tbody>
  </table></div>`;
}

function renderRecentRequests(requests) {
  const host = document.getElementById('recent-requests');
  if (!host) return;
  if (!requests.length) {
    host.innerHTML = '<div class="empty">No deletion requests yet.</div>';
    return;
  }
  host.innerHTML = `<div class="table-wrap"><table class="data">
    <thead><tr><th>Requested</th><th>Kind</th><th>Status</th><th class="num">Erased</th><th class="num">Blocked</th></tr></thead>
    <tbody>
      ${requests.slice(0, 7).map((r) => `<tr class="clickable" data-req="${esc(r.id)}">
        <td class="secondary">${fmtDate(r.requestedAt)}<div class="muted" style="font-size:11px">${esc(r.requestedBy)}</div></td>
        <td>${r.kind === 'subject_erasure' ? 'Subject erasure' : 'Retention sweep'}</td>
        <td>${statusBadge(r.status)}</td>
        <td class="num">${n(r.itemErased)}<span class="muted">/${n(r.itemTotal)}</span></td>
        <td class="num">${n(r.itemBlocked)}</td>
      </tr>`).join('')}
    </tbody>
  </table></div>`;
  host.querySelectorAll('[data-req]').forEach((tr) => {
    tr.addEventListener('click', () => openRequest(tr.dataset.req));
  });
}

function renderRejections(rejections) {
  const host = document.getElementById('rejections-panel');
  if (!host) return;
  if (!rejections.length) {
    host.innerHTML = '<div class="empty">No writes have been rejected. Open a sweep and re-ingest older data to see the fence act.</div>';
    return;
  }
  host.innerHTML = `<div class="table-wrap"><table class="data">
    <thead><tr><th>Attempted</th><th>Layer</th><th>Subject token</th><th>Event time</th><th>Reason</th></tr></thead>
    <tbody>
      ${rejections.map((r) => `<tr>
        <td class="secondary">${fmtDate(r.attemptedAt)}</td>
        <td>${badge(r.layer, 'neutral')}</td>
        <td class="mono truncate">${esc(r.subjectToken)}</td>
        <td class="secondary num">${fmtDate(r.occurredAt)}</td>
        <td>${badge('fenced range', 'warn')}</td>
      </tr>`).join('')}
    </tbody>
  </table></div>`;
}

// ===========================================================================
// Dialogs
// ===========================================================================

function openModal({ title, body, actions = [], onMount }) {
  closeModal();
  const overlay = el(`<div class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal">
      <div class="modal-head">
        <h3 id="modal-title">${esc(title)}</h3>
        <button class="icon-btn" id="modal-close" aria-label="Close" type="button">✕</button>
      </div>
      <div class="modal-body"></div>
      <div class="modal-foot"></div>
    </div>
  </div>`);
  overlay.querySelector('.modal-body').appendChild(typeof body === 'string' ? el(`<div>${body}</div>`) : body);
  const foot = overlay.querySelector('.modal-foot');
  for (const a of actions) {
    const btn = el(`<button class="btn ${a.kind || ''}" type="button">${esc(a.label)}</button>`);
    btn.addEventListener('click', () => a.onClick(btn));
    foot.appendChild(btn);
  }
  document.body.appendChild(overlay);
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) closeModal(); });
  overlay.querySelector('#modal-close').addEventListener('click', closeModal);
  document.addEventListener('keydown', escClose);
  if (onMount) onMount(overlay);
  overlay.querySelector('.modal-body').querySelector('input,select,textarea,button')?.focus();
  return overlay;
}

function escClose(e) { if (e.key === 'Escape') closeModal(); }

function closeModal() {
  document.querySelectorAll('.modal-overlay').forEach((n) => n.remove());
  document.removeEventListener('keydown', escClose);
}

function openSweepDialog() {
  const p = state.overview.pending;
  const body = el(`<div class="stack">
    <div class="callout">
      <div>A retention sweep deletes every object older than its layer's cut-off, then opens a
      <strong>watermark fence</strong> so late writes for that range cannot re-enter it.</div>
    </div>
    <div class="table-wrap"><table class="data">
      <thead><tr><th>Layer</th><th>Retain</th><th>Cut-off</th><th class="num">Eligible</th><th class="num">Blocked</th></tr></thead>
      <tbody>
        ${p.map((l) => `<tr>
          <td><label style="display:flex;gap:8px;align-items:center;cursor:pointer">
            <input type="checkbox" data-layer="${esc(l.layer)}" checked ${l.sweepEligible === 0 ? 'disabled' : ''}>
            <span class="layer-swatch" style="background:${LAYER_COLOR[l.layer]}"></span>${esc(l.label)}
          </label></td>
          <td class="secondary">${esc(windowLabel(l.policy))}</td>
          <td class="secondary">${fmtDate(l.cutoffMs)}</td>
          <td class="num" style="font-weight:600">${n(l.sweepEligible)}</td>
          <td class="num">${n(l.blockedCount)}</td>
        </tr>`).join('')}
      </tbody>
    </table></div>
    <div class="muted" style="font-size:12px">Objects blocked by a legal hold or statutory floor are listed in the manifest but are not deleted; they stay visible as exceptions on the proof.</div>
  </div>`);
  openModal({
    title: 'Run retention sweep',
    body,
    actions: [
      { label: 'Cancel', onClick: closeModal },
      {
        label: 'Create manifest & execute',
        kind: 'primary',
        onClick: async (btn) => {
          const layers = [...body.querySelectorAll('input[data-layer]:checked')].map((i) => i.dataset.layer);
          if (!layers.length) { toast('Select at least one layer', true); return; }
          btn.disabled = true;
          try {
            const res = await run(() => api('POST', T('/requests'), { kind: 'retention_sweep', layers }));
            closeModal();
            toast(`Sweep ${res.execution?.status || 'created'}: ${n(res.execution?.erased || 0)} erased, ${n(res.execution?.blocked || 0)} blocked`);
            await openRequest(res.requestId);
          } catch { btn.disabled = false; }
        },
      },
    ],
  });
}

async function openInspectDialog() {
  const body = el(`<div class="stack">
    <div class="field">
      <label for="inspect-subject">Subject identifier</label>
      <input id="inspect-subject" placeholder="e.g. alice@example.com" autocomplete="off">
      <span class="help">Used to derive an opaque token; the value is not stored in the manifest or audit.</span>
    </div>
    <div id="inspect-result" class="muted" style="font-size:12.5px"></div>
  </div>`);
  const overlay = openModal({
    title: 'Inspect a subject',
    body,
    actions: [
      { label: 'Close', onClick: closeModal },
      {
        label: 'Inspect',
        kind: 'primary',
        onClick: async () => {
          const subjectRef = body.querySelector('#inspect-subject').value.trim();
          if (!subjectRef) { toast('Enter a subject identifier', true); return; }
          const out = body.querySelector('#inspect-result');
          out.innerHTML = '<span class="spinner"></span>';
          try {
            const res = await run(() => api('POST', T('/subjects/inspect'), { subjectRef }));
            state.subjectInspect = res;
            out.innerHTML = renderInspectResult(res, subjectRef);
            const eraseBtn = out.querySelector('#inspect-erase');
            eraseBtn?.addEventListener('click', async () => {
              eraseBtn.disabled = true;
              try {
                const created = await run(() => api('POST', T('/requests'), { kind: 'subject_erasure', subjectRef }));
                closeModal();
                toast(`Erasure ${created.execution?.status || 'created'}: ${n(created.execution?.erased || 0)} erased, ${n(created.execution?.blocked || 0)} blocked`);
                await openRequest(created.requestId);
              } catch { eraseBtn.disabled = false; }
            });
          } catch { out.textContent = 'Inspection failed.'; }
        },
      },
    ],
  });
  overlay.querySelector('#inspect-subject').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') overlay.querySelectorAll('.modal-foot .btn.primary')[0].click();
  });
}

function renderInspectResult(res, subjectRef) {
  const rows = res.layers.map((l) => `<tr>
    <td>${esc(l.label)}</td>
    <td class="num" style="font-weight:600">${n(l.total)}</td>
    <td class="num">${n(l.eligible)}</td>
    <td class="num">${n(l.blockedCount)}</td>
    <td>${l.blockedCount ? badge(l.blocked[0]?.blocker?.reason === 'statutory_minimum' ? 'statutory' : 'held', 'warn') : ''}</td>
  </tr>`).join('');
  return `<div class="sep"></div>
    <div class="kv" style="margin-bottom:10px">
      <dt>Opaque token</dt><dd class="mono">${esc(res.subjectToken)}</dd>
      <dt>Eligible</dt><dd><strong>${n(res.totalEligible)}</strong> objects</dd>
      <dt>Blocked</dt><dd><strong>${n(res.totalBlocked)}</strong> objects</dd>
    </div>
    <div class="table-wrap"><table class="data">
      <thead><tr><th>Layer</th><th class="num">Total</th><th class="num">Eligible</th><th class="num">Blocked</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    <div class="row-actions" style="margin-top:12px">
      <button class="btn danger small" id="inspect-erase" ${res.totalEligible === 0 ? 'disabled' : ''}>Create erasure request</button>
    </div>`;
}



// ===========================================================================
// Requests & proofs
// ===========================================================================

async function renderRequests() {
  await loadRequests();
  const reqs = state.requests;
  app.innerHTML = `
    <div class="section">
      <div class="section-head">
        <h2>Deletion requests</h2>
        <span class="hint">${n(reqs.length)} requests · manifests are immutable once generated</span>
      </div>
      <div class="card">
        ${reqs.length === 0
          ? '<div class="empty">No requests yet. Run a retention sweep from the Overview tab.</div>'
          : `<div class="table-wrap"><table class="data">
              <thead><tr>
                <th>Requested</th><th>Kind</th><th>Status</th>
                <th class="num">Items</th><th class="num">Erased</th><th class="num">Blocked</th><th>Proof</th>
              </tr></thead>
              <tbody>
                ${reqs.map((r) => `<tr class="clickable" data-req="${esc(r.id)}">
                  <td class="secondary">${fmtDate(r.requestedAt)}<div class="muted" style="font-size:11px">${esc(r.requestedBy)}</div></td>
                  <td>${r.kind === 'subject_erasure' ? 'Subject erasure' : 'Retention sweep'}</td>
                  <td>${statusBadge(r.status)}</td>
                  <td class="num">${n(r.itemTotal)}</td>
                  <td class="num" style="font-weight:600">${n(r.itemErased)}</td>
                  <td class="num">${n(r.itemBlocked)}</td>
                  <td>${r.proofId ? badge('issued', 'info') : '<span class="muted">—</span>'}</td>
                </tr>`).join('')}
              </tbody>
            </table></div>`}
      </div>
    </div>
    <div id="request-detail"></div>
  `;
  app.querySelectorAll('[data-req]').forEach((tr) => {
    tr.addEventListener('click', () => openRequest(tr.dataset.req));
  });
  if (state.requestDetail) {
    renderRequestDetail(state.requestDetail);
  }
}

async function openRequest(requestId) {
  closeModal();
  try {
    setLoading(true);
    const detail = await api('GET', T(`/requests/${requestId}`));
    state.requestDetail = detail;
    state.proofView = null;
    if (state.tab !== 'requests') setTab('requests');
    renderRequestDetail(detail);
  } catch (err) {
    toast(err.message, true);
  } finally {
    setLoading(false);
  }
}

function renderRequestDetail(d) {
  const host = document.getElementById('request-detail');
  if (!host) return;
  const r = d.request;
  const p = d.progress;
  host.innerHTML = `
    <div class="section">
      <div class="section-head">
        <h2>${r.kind === 'subject_erasure' ? 'Subject erasure' : 'Retention sweep'} · <span class="mono" style="font-weight:500;font-size:13px">${esc(r.id)}</span></h2>
        <span class="hint">${statusBadge(r.status)}</span>
      </div>
      <div class="card">
        <div class="detail-head">
          <div class="stack" style="gap:10px">
            <div class="kv">
              <dt>Requested</dt><dd>${fmtDate(r.requestedAt)} by ${esc(r.requestedBy)}</dd>
              <dt>Manifest</dt><dd class="mono">${esc(r.manifestId)}</dd>
              <dt>Manifest hash</dt><dd class="hash">${esc(r.manifestHash)}</dd>
              ${d.manifest?.subjectToken ? `<dt>Subject token</dt><dd class="mono">${esc(d.manifest.subjectToken)}</dd>` : ''}
              ${r.finishedAt ? `<dt>Finished</dt><dd>${fmtDate(r.finishedAt)}</dd>` : ''}
            </div>
          </div>
          <div class="row-actions">
            ${['awaiting_execution', 'blocked'].includes(r.status) ? `<button class="btn primary small" id="btn-execute">Execute request</button>` : ''}
            ${d.proof ? `<button class="btn small" id="btn-verify">Verify proof</button>
                         <button class="btn small" id="btn-proof">View proof</button>` : ''}
          </div>
        </div>

        <div class="card-pad" style="border-bottom:1px solid var(--grid)">
          <div class="flex-between" style="margin-bottom:8px">
            <h3 style="font-size:13px">Execution progress</h3>
            <span class="muted num" style="font-size:12px">${n(p.settled)} of ${n(p.total)} settled</span>
          </div>
          ${progressBar(p)}
          <div class="legend" style="margin-top:10px">
            <span class="item"><span class="swatch" style="background:var(--series-1)"></span>Erased ${n(p.erased)}</span>
            <span class="item"><span class="swatch" style="background:var(--serious)"></span>Blocked ${n(p.blocked)}</span>
            <span class="item"><span class="swatch" style="background:var(--grid)"></span>Skipped ${n(p.skipped)}</span>
            ${p.pending ? `<span class="item"><span class="swatch" style="background:var(--axis)"></span>Pending ${n(p.pending)}</span>` : ''}
          </div>
        </div>

        ${renderLayerBreakdown(d)}

        <div class="card-pad">
          <h3 style="font-size:13px;margin-bottom:8px">Blocking reasons</h3>
          ${d.blockerSummary.length === 0
            ? '<p class="muted" style="font-size:12.5px">Nothing was blocked — every manifest item was eligible.</p>'
            : `<div class="table-wrap"><table class="data">
                <thead><tr><th>Reason</th><th>Legal basis</th><th class="num">Objects</th></tr></thead>
                <tbody>
                  ${d.blockerSummary.map((b) => {
                    const hold = d.holdsAffected.find((h) => h.id === b.holdRef);
                    return `<tr>
                      <td>${blockerLabel(b.reason)}</td>
                      <td class="secondary">${esc(hold?.legalBasis || 'Layer statutory floor')}
                        ${hold?.expiresAt ? `<div class="muted" style="font-size:11px">expires ${fmtDay(hold.expiresAt)}</div>` : ''}</td>
                      <td class="num" style="font-weight:600">${n(b.count)}</td>
                    </tr>`;
                  }).join('')}
                </tbody></table></div>`}
        </div>

        ${d.proof ? renderProofSummary(d.proof) : ''}
      </div>
    </div>
    <div id="proof-detail"></div>
  `;

  const btnExec = document.getElementById('btn-execute');
  if (btnExec) btnExec.addEventListener('click', async () => {
    btnExec.disabled = true;
    try {
      await run(() => api('POST', T(`/requests/${r.id}/execute`)), { success: 'Request executed' });
      await openRequest(r.id);
      await loadOverview();
    } catch { btnExec.disabled = false; }
  });
  const btnVerify = document.getElementById('btn-verify');
  if (btnVerify) btnVerify.addEventListener('click', async () => {
    btnVerify.disabled = true;
    try {
      const res = await run(() => api('POST', T(`/requests/${r.id}/verify`)));
      const v = res.verification;
      const failed = v.checks.filter((c) => !c.ok);
      toast(v.ok ? 'Proof verified — all checks passed' : `Verification failed (${failed.length} check${failed.length === 1 ? '' : 's'})`, !v.ok);
      await openRequest(r.id);
      showVerification(v);
    } catch { btnVerify.disabled = false; }
  });
  const btnProof = document.getElementById('btn-proof');
  if (btnProof) btnProof.addEventListener('click', () => showProof(r.id));

  host.querySelectorAll('[data-item-toggle]').forEach((b) => {
    b.addEventListener('click', () => {
      const row = document.getElementById(b.dataset.itemToggle);
      row.hidden = !row.hidden;
    });
  });
}

function progressBar(p) {
  const total = Math.max(1, p.total);
  const seg = (count, cls, label) => count > 0
    ? `<span class="seg ${cls}" style="width:${(count / total) * 100}%;flex:none"
        data-pie="${count}|${label}"></span>` : '';
  return `<div class="meter" style="height:12px" role="img" aria-label="${n(p.erased)} erased, ${n(p.blocked)} blocked, ${n(p.skipped)} skipped, ${n(p.pending)} pending of ${n(p.total)}">
    ${seg(p.erased, 'erase', 'erased')}
    ${seg(p.blocked, 'block', 'blocked')}
    ${seg(p.skipped, 'skip', 'skipped')}
    ${seg(p.pending, 'pending', 'pending')}
  </div>`;
}

function renderLayerBreakdown(d) {
  return `<div class="card-pad" style="border-bottom:1px solid var(--grid)">
    <h3 style="font-size:13px;margin-bottom:10px">Per-layer outcome</h3>
    <div class="table-wrap"><table class="data">
      <thead><tr><th>Layer</th><th>Cut-off</th><th>Policy v</th><th class="num">Items</th><th class="num">Erased</th><th class="num">Blocked</th><th class="num">Skipped</th><th class="num">Pending</th></tr></thead>
      <tbody>
        ${d.byLayer.map((l) => `<tr>
          <td><span class="layer-name" style="gap:7px"><span class="layer-swatch" style="background:${LAYER_COLOR[l.layer]}"></span>${esc(l.layer)}</span></td>
          <td class="secondary">${l.cutoffMs ? fmtDate(l.cutoffMs) : '<span class="muted">—</span>'}</td>
          <td class="secondary num">${l.policyVersion ?? '—'}</td>
          <td class="num">${n(l.total)}</td>
          <td class="num" style="font-weight:600">${n(l.erased)}</td>
          <td class="num">${n(l.blocked)}</td>
          <td class="num">${n(l.skipped)}</td>
          <td class="num">${n(l.pending)}</td>
        </tr>`).join('')}
      </tbody>
    </table></div>
    ${d.batches.length ? `<div class="muted" style="font-size:11.5px;margin-top:9px">
      ${d.batches.length} committed batch${d.batches.length === 1 ? '' : 'es'} · chained commitment roots:
      ${d.batches.slice(0, 3).map((b) => `<span class="mono">${esc(b.commitmentRoot.slice(0, 16))}…</span>`).join(' → ')}
    </div>` : ''}
  </div>`;
}

function blockerLabel(reason) {
  const map = {
    legal_hold_subject: badge('Legal hold · subject', 'warn'),
    legal_hold_tenant: badge('Legal hold · tenant', 'warn'),
    legal_hold_range: badge('Legal hold · range', 'warn'),
    statutory_minimum: badge('Statutory minimum', 'warn'),
  };
  return map[reason] || badge(reason, 'neutral');
}

function renderProofSummary(proof) {
  const v = proof.verification;
  const state_ = !v ? badge('Not yet verified', 'neutral')
    : v.ok ? badge('Verified', 'good') : badge('Verification failed', 'crit');
  return `<div class="card-pad">
    <div class="flex-between" style="margin-bottom:10px">
      <h3 style="font-size:13px">Erasure proof</h3>
      ${state_}
    </div>
    <div class="kv">
      <dt>Proof ID</dt><dd class="mono">${esc(proof.id)}</dd>
      <dt>Merkle root</dt><dd class="hash">${esc(proof.merkleRoot)}</dd>
      <dt>Document hash</dt><dd class="hash">${esc(proof.proofHash)}</dd>
      ${v ? `<dt>Verified</dt><dd>${fmtDate(v.verifiedAt)} by ${esc(v.verifiedBy)}</dd>` : ''}
    </div>
    ${v ? `<div class="sep"></div><ul class="check-list">
      ${v.checks.map((c) => `<li>
        <span class="check-icon ${c.ok ? 'ok' : 'fail'}">${c.ok ? '✓' : '✕'}</span>
        <div>
          <div class="check-label">${esc(c.label)}</div>
          ${!c.ok ? `<div class="check-detail">${esc(tidyDetail(c.detail))}</div>` : ''}
        </div>
      </li>`).join('')}
    </ul>` : `<p class="muted" style="font-size:12.5px;margin-top:8px">Run verification to re-check deletion, manifest binding, Merkle inclusion and the audit chain.</p>`}
  </div>`;
}

function tidyDetail(detail) {
  if (detail == null) return '';
  if (typeof detail === 'string') return detail.length > 300 ? detail.slice(0, 300) + '…' : detail;
  return JSON.stringify(detail).slice(0, 300);
}

async function showProof(requestId) {
  try {
    setLoading(true);
    const { proof } = await api('GET', T(`/requests/${requestId}/proof`));
    state.proofView = proof;
    const body = el(`<div class="stack">
      <div class="callout">
        <div>Commitments are keyed HMACs over the removed content. They prove <em>what was removed</em>
        without disclosing any field values — no subject identifiers, amounts, or payloads appear here.</div>
      </div>
      <div class="kv">
        <dt>Proof ID</dt><dd class="mono">${esc(proof.proofId)}</dd>
        <dt>Merkle root</dt><dd class="hash">${esc(proof.merkleRoot)}</dd>
        <dt>Document hash</dt><dd class="hash">${esc(proof.proofHash)}</dd>
        <dt>Key fingerprint</dt><dd class="mono">${esc(proof.keyFingerprint)}</dd>
        <dt>Leaves</dt><dd>${n(proof.counts.proofLeaves)} · ${n(proof.counts.erased)} erased · ${n(proof.counts.blocked)} blocked · ${n(proof.counts.skipped)} skipped</dd>
      </div>
      <div>
        <h4 style="font-size:12.5px;margin-bottom:6px">Committed batches</h4>
        <div class="table-wrap"><table class="data">
          <thead><tr><th class="num">#</th><th>Layer</th><th class="num">Leaves</th><th>Root</th><th>Prev</th></tr></thead>
          <tbody>${proof.batches.map((b) => `<tr>
            <td class="num">${b.seq}</td><td>${esc(b.layer)}</td>
            <td class="num">${n(b.itemCount)}</td>
            <td class="hash">${esc(b.commitmentRoot.slice(0, 24))}…</td>
            <td class="hash">${b.prevRoot ? esc(b.prevRoot.slice(0, 12)) + '…' : '<span class="muted">genesis</span>'}</td>
          </tr>`).join('')}</tbody>
        </table></div>
      </div>
      <div>
        <h4 style="font-size:12.5px;margin-bottom:6px">Sampled inclusion paths (${proof.samplePaths.length})</h4>
        <div class="table-wrap" style="max-height:230px;overflow:auto"><table class="data">
          <thead><tr><th class="num">Leaf</th><th>Object</th><th>Commitment</th></tr></thead>
          <tbody>${proof.samplePaths.map((p) => `<tr>
            <td class="num">${p.leafIndex}</td>
            <td class="mono">${esc(p.objectRef)}</td>
            <td class="hash">${esc(p.commitment.slice(0, 28))}…</td>
          </tr>`).join('')}</tbody>
        </table></div>
      </div>
      <details>
        <summary class="secondary" style="cursor:pointer;font-size:12.5px">Raw proof document (JSON)</summary>
        <pre class="mono" style="white-space:pre-wrap;font-size:11px;max-height:280px;overflow:auto;background:var(--page);padding:12px;border-radius:6px;margin-top:8px">${esc(JSON.stringify(proof, null, 2))}</pre>
      </details>
    </div>`);
    openModal({
      title: 'Erasure proof',
      body,
      actions: [
        { label: 'Download JSON', onClick: () => downloadProof(proof) },
        { label: 'Close', kind: 'primary', onClick: closeModal },
      ],
    });
  } catch (err) {
    toast(err.message, true);
  } finally {
    setLoading(false);
  }
}

function showVerification(v) {
  const body = el(`<div class="stack">
    <div class="callout ${v.ok ? '' : 'warn'}">
      <div><strong>${v.ok ? 'All checks passed.' : 'One or more checks failed.'}</strong>
      Re-verified at ${fmtDate(v.verifiedAt)} by ${esc(v.verifiedBy)}.</div>
    </div>
    <ul class="check-list">
      ${v.checks.map((c) => `<li>
        <span class="check-icon ${c.ok ? 'ok' : 'fail'}">${c.ok ? '✓' : '✕'}</span>
        <div>
          <div class="check-label">${esc(c.label)}</div>
          <div class="check-detail">${esc(tidyDetail(c.detail))}</div>
        </div>
      </li>`).join('')}
    </ul>
  </div>`);
  openModal({ title: 'Proof verification', body, actions: [{ label: 'Close', kind: 'primary', onClick: closeModal }] });
}

function downloadProof(proof) {
  const blob = new Blob([JSON.stringify(proof, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `proof-${proof.requestId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ===========================================================================
// Policies & holds
// ===========================================================================

async function renderPoliciesView() {
  await loadOverview();
  const o = state.overview;
  app.innerHTML = `
    <div class="section">
      <div class="section-head">
        <h2>Retention policy</h2>
        <span class="hint">Changes create a new version; the statutory floor can never be undercut</span>
      </div>
      <div class="card"><div id="policy-table"></div></div>
    </div>
    <div class="section">
      <div class="section-head">
        <h2>Legal holds</h2>
        <span class="hint">Holds override erasure until released or expired</span>
      </div>
      <div class="card"><div id="holds-table"></div></div>
    </div>
  `;
  renderPolicyTable(o.policies);
  renderHoldsTable(o.holds);
}

function renderPolicyTable(policies) {
  const host = document.getElementById('policy-table');
  host.innerHTML = `<div class="table-wrap"><table class="data">
    <thead><tr>
      <th>Layer</th><th>Retain for</th><th>Statutory floor</th><th>Legal basis</th><th class="num">Version</th><th></th>
    </tr></thead>
    <tbody>
      ${policies.map((p) => `<tr data-layer="${esc(p.layer)}">
        <td><span class="layer-name" style="gap:7px"><span class="layer-swatch" style="background:${LAYER_COLOR[p.layer]}"></span>${esc(p.label)}</span>
          <div class="muted" style="font-size:11px">cut-off ${fmtDate(p.cutoffMs)}</div></td>
        <td class="secondary">${esc(windowLabel(p))}</td>
        <td>${p.statutoryMinDays ? `<span class="secondary">${p.statutoryMinDays} days</span>
             <div class="muted" style="font-size:11px">${esc(p.statutoryBasis || '')}</div>` : '<span class="muted">none</span>'}</td>
        <td class="secondary">${esc(p.legalBasis)}${p.exceptionNote ? `<div class="muted" style="font-size:11px">${esc(p.exceptionNote)}</div>` : ''}</td>
        <td class="num secondary">v${p.version || '—'}</td>
        <td><button class="btn small" data-edit="${esc(p.layer)}">Edit</button></td>
      </tr>`).join('')}
    </tbody>
  </table></div>`;
  host.querySelectorAll('[data-edit]').forEach((btn) => {
    btn.addEventListener('click', () => openPolicyEditor(policies.find((p) => p.layer === btn.dataset.edit)));
  });
}

function openPolicyEditor(policy) {
  const body = el(`<div class="stack">
    <div class="callout">
      <div>Saving creates <strong>version ${(policy.version || 0) + 1}</strong>. Existing manifests keep the
      policy version they were generated against; new sweeps use the new cut-off.</div>
    </div>
    <div class="form-grid">
      <div class="field">
        <label for="pol-value">Retain for</label>
        <div class="field-row">
          <input id="pol-value" type="number" min="1" step="1" value="${policy.retentionValue}">
          <select id="pol-unit" aria-label="Retention unit">
            <option value="hours" ${policy.retentionUnit === 'hours' ? 'selected' : ''}>hours</option>
            <option value="days" ${policy.retentionUnit === 'days' ? 'selected' : ''}>days</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label for="pol-statutory">Statutory minimum (days)</label>
        <input id="pol-statutory" type="number" min="0" step="1" value="${policy.statutoryMinDays}">
        <span class="help">Objects younger than this cannot be erased even on request.</span>
      </div>
      <div class="field full">
        <label for="pol-basis">Legal basis</label>
        <input id="pol-basis" value="${esc(policy.legalBasis)}">
      </div>
      <div class="field full">
        <label for="pol-statutory-basis">Statutory basis</label>
        <input id="pol-statutory-basis" value="${esc(policy.statutoryBasis || '')}" placeholder="e.g. 7-year financial records rule">
      </div>
      <div class="field full">
        <label for="pol-note">Exception note</label>
        <textarea id="pol-note" placeholder="Optional note shown to operators">${esc(policy.exceptionNote || '')}</textarea>
      </div>
    </div>
    <div id="pol-error" class="callout warn" hidden></div>
  </div>`);

  openModal({
    title: `Edit ${policy.label} policy`,
    body,
    actions: [
      { label: 'Cancel', onClick: closeModal },
      {
        label: 'Save new version',
        kind: 'primary',
        onClick: async (btn) => {
          const patch = {
            retentionValue: Number(body.querySelector('#pol-value').value),
            retentionUnit: body.querySelector('#pol-unit').value,
            statutoryMinDays: Number(body.querySelector('#pol-statutory').value),
            legalBasis: body.querySelector('#pol-basis').value.trim(),
            statutoryBasis: body.querySelector('#pol-statutory-basis').value.trim(),
            exceptionNote: body.querySelector('#pol-note').value.trim(),
          };
          btn.disabled = true;
          try {
            await run(() => api('PATCH', T(`/policies/${policy.layer}`), patch), { success: `${policy.label} policy updated` });
            closeModal();
            await renderPoliciesView();
          } catch (err) {
            const box = body.querySelector('#pol-error');
            box.hidden = false;
            box.textContent = err.message;
            btn.disabled = false;
          }
        },
      },
    ],
  });
}

function renderHoldsTable(holds) {
  const host = document.getElementById('holds-table');
  if (!holds.length) {
    host.innerHTML = '<div class="empty">No legal holds. All deletion is governed by policy alone.</div>';
    return;
  }
  host.innerHTML = `<div class="table-wrap"><table class="data">
    <thead><tr><th>Scope</th><th>Layer</th><th>Reason</th><th>Legal basis</th><th>Status</th><th>Expires</th><th></th></tr></thead>
    <tbody>
      ${holds.map((h) => `<tr>
        <td>
          <div style="font-weight:600">${esc(h.scopeKind === 'tenant' ? 'Whole tenant' : h.scopeKind === 'subject' ? 'Subject' : 'Date range')}</div>
          ${h.subjectLabel ? `<div class="muted" style="font-size:11.5px">${esc(h.subjectLabel)}</div>` : ''}
          ${h.scopeKind === 'date_range' ? `<div class="muted" style="font-size:11px">${fmtDay(h.fromMs)} – ${fmtDay(h.toMs)}</div>` : ''}
        </td>
        <td>${h.layer ? badge(h.layer, 'neutral') : '<span class="muted">all</span>'}</td>
        <td class="secondary">${esc(h.reason)}</td>
        <td class="secondary">${esc(h.legalBasis)}<div class="muted" style="font-size:11px">${esc(h.placedBy)} · ${fmtDate(h.placedAt)}</div></td>
        <td>${h.active ? badge('Active', 'warn') : badge(h.status, 'neutral')}</td>
        <td class="secondary">${h.expiresAt ? fmtDay(h.expiresAt) : '<span class="muted">no expiry</span>'}</td>
        <td>${h.active ? `<button class="btn small" data-release="${esc(h.id)}">Release</button>` : ''}</td>
      </tr>`).join('')}
    </tbody>
  </table></div>`;

  host.querySelectorAll('[data-release]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const holdId = btn.dataset.release;
      openModal({
        title: 'Release legal hold',
        body: '<p class="secondary" style="font-size:13px">Releasing this hold makes the objects it covered eligible for deletion again. The release is recorded on the audit chain.</p>',
        actions: [
          { label: 'Cancel', onClick: closeModal },
          {
            label: 'Release hold',
            kind: 'danger',
            onClick: async (b) => {
              b.disabled = true;
              try {
                await run(() => api('POST', T(`/holds/${holdId}/release`)), { success: 'Hold released' });
                closeModal();
                await renderPoliciesView();
              } catch { b.disabled = false; }
            },
          },
        ],
      });
    });
  });
}

// ===========================================================================
// Audit trail
// ===========================================================================

async function renderAudit() {
  await Promise.all([loadAudit(), loadOverview()]);
  const events = [...state.audit].reverse();
  const ov = state.overview || {};
  app.innerHTML = `
    <div class="section">
      <div class="section-head">
        <h2>Audit trail</h2>
        <span class="hint">Append-only per-tenant hash chain · ${n(state.audit.length)} events shown</span>
      </div>
      ${ov.audit ? `<div class="callout ${ov.audit.valid ? '' : 'warn'}" style="margin-bottom:14px">
        <div>${ov.audit.valid
          ? `<strong>Chain verified.</strong> Head <span class="mono">${esc((ov.audit.head || '').slice(0, 16))}…</span> over ${n(ov.audit.checked)} events.`
          : '<strong>Chain verification failed.</strong> Events may have been altered or removed.'}</div>
      </div>` : ''}
      <div class="card"><div class="card-pad">
        ${events.length === 0 ? '<div class="empty">No audit events.</div>' : `<ul class="timeline">
          ${events.map((e) => `<li>
            <span class="node"></span>
            <div class="t-top">
              <span class="t-type">${esc(e.type)}</span>
              <span class="t-time">${fmtDate(e.at)} · ${esc(e.actor)}</span>
            </div>
            <div class="t-body">${esc(summarizeEvent(e))}</div>
            <div class="mono muted" style="font-size:10.5px;margin-top:2px">seq ${e.seq} · ${esc(e.hash.slice(0, 20))}…</div>
          </li>`).join('')}
        </ul>`}
      </div></div>
    </div>
  `;
}

/**
 * Render only opaque metadata from the event payload. Values are summarised,
 * never dumped, so the audit view cannot become a side channel for deleted data.
 */
function summarizeEvent(e) {
  const p = e.payload || {};
  const parts = [];
  const push = (k, v) => { if (v !== undefined && v !== null && v !== '') parts.push(`${k}: ${v}`); };
  if (p.kind) push('kind', p.kind);
  if (p.layer) push('layer', p.layer);
  if (p.manifestHash) push('manifest', String(p.manifestHash).slice(0, 12) + '…');
  if (p.itemTotal != null) push('items', p.itemTotal);
  if (p.alreadyBlocked != null) push('pre-blocked', p.alreadyBlocked);
  if (p.fences) push('fences', p.fences.length);
  if (p.erased != null) push('erased', p.erased);
  if (p.blocked != null) push('blocked', p.blocked);
  if (p.skipped != null) push('skipped', p.skipped);
  if (p.status) push('status', p.status);
  if (p.merkleRoot) push('root', String(p.merkleRoot).slice(0, 12) + '…');
  if (p.proofId) push('proof', p.proofId);
  if (p.checks) push('checks', `${p.checks.filter((c) => c.ok).length}/${p.checks.length} passed`);
  if (p.generation != null) push('generation', p.generation);
  if (p.accepted != null) push('accepted', p.accepted);
  if (p.rejected != null) push('rejected', p.rejected);
  if (p.holdId) push('hold', p.holdId);
  if (p.scopeKind) push('scope', p.scopeKind);
  if (p.tenant) push('tenant', p.tenant);
  if (p.error) push('error', p.error);
  if (p.previous && p.next) push('window', `${p.previous.retentionValue}${p.previous.retentionUnit} → ${p.next.retentionValue}${p.next.retentionUnit}`);
  if (p.batchNo != null) push('batch', p.batchNo);
  if (p.leaves != null) push('leaves', p.leaves);
  if (p.keyFingerprint) push('key', p.keyFingerprint);
  return parts.join(' · ') || '—';
}

// Delegated tooltip for meter segments rendered on any tab.
document.addEventListener('pointermove', (e) => {
  const seg = e.target.closest('[data-pie]');
  if (!seg) return;
  const [value, label] = seg.dataset.pie.split('|');
  showTip(e, `<div class="tt-value">${esc(value)}</div><div class="tt-label">${esc(label)}</div>`);
});
document.addEventListener('pointerout', (e) => {
  if (e.target.closest('[data-pie]')) hideTip();
});
