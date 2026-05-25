/* IMMUTRACE Audit Dashboard — vanilla JS */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function fmtTs(ts) {
  if (!ts) return "—";
  return ts.replace("T", " ").replace("Z", "").slice(0, 23);
}

function statusClass(s) {
  if (!s) return "";
  const d = String(s)[0];
  return `status-${d}`;
}

async function api(path) {
  const r = await fetch(path, { credentials: "same-origin" });
  if (!r.ok) throw new Error(`${path} → ${r.status}`);
  return r.json();
}

async function loadSessions() {
  const data = await api("/_immutrace/audit/sessions");
  const list = $("#sessions-list");
  list.innerHTML = "";
  if (!data.sessions.length) {
    list.innerHTML = '<p class="muted">No sessions yet. Open the proxied OSIRIS UI and start one.</p>';
    return;
  }
  for (const s of data.sessions) {
    const isExpired = new Date(s.expires_at) < new Date();
    const active = !s.revoked && !isExpired;
    const card = document.createElement("div");
    card.className = "session-card";
    card.innerHTML = `
      <div class="sid">${escapeHtml(s.session_id)}</div>
      <div class="actor">${escapeHtml(s.actor)}</div>
      <div>
        <span class="pill">${escapeHtml(s.activity_type || "—")}</span>
        ${s.case_id ? `<span class="pill">case ${escapeHtml(s.case_id)}</span>` : ""}
        <span class="pill ${active ? "active" : s.revoked ? "revoked" : ""}">
          ${active ? "● active" : s.revoked ? "✕ revoked" : "expired"}
        </span>
      </div>
      <div class="just">${escapeHtml(s.justification)}</div>
      <div class="meta">
        <span><b>${s.event_count}</b> events</span>
        <span>Created: ${fmtTs(s.created_at)}</span>
        <span>Expires: ${fmtTs(s.expires_at)}</span>
      </div>
      <div class="row-btns">
        <button onclick="verifyChain('${s.session_id}')">Verify chain</button>
        <button onclick="showEvents('${s.session_id}')">View events</button>
        <a href="/_immutrace/audit/export/${s.session_id}.pdf" target="_blank">Download PDF</a>
      </div>
    `;
    list.appendChild(card);
  }
}

async function loadEvents(sessionId, caseId, actor, risk, tsFrom, tsTo) {
  const params = new URLSearchParams();
  if (sessionId) params.set("session_id", sessionId);
  if (caseId) params.set("case_id", caseId);
  if (actor) params.set("actor", actor);
  if (risk) params.set("risk", risk);
  if (tsFrom) params.set("ts_from", tsFrom);
  if (tsTo) params.set("ts_to", tsTo);
  params.set("limit", "300");
  const data = await api("/_immutrace/audit/events?" + params.toString());
  const list = $("#events-list");
  if (!data.events.length) {
    list.innerHTML = '<p class="muted">No events match. Open OSIRIS through the proxy and click around.</p>';
    return;
  }
  let html = `<table class="events">
    <thead><tr>
      <th>#</th><th>Timestamp UTC</th><th>Session</th><th>Actor</th>
      <th>Type</th><th>Method</th><th>Path</th><th>Status</th><th>eIDAS</th><th>Hash</th>
    </tr></thead><tbody>`;
  // events come newest-first; render in given order
  for (const e of data.events) {
    html += `<tr>
      <td>${e.id}</td>
      <td class="mono">${fmtTs(e.ts)}</td>
      <td class="mono">${escapeHtml(e.session_id.slice(0, 8))}…</td>
      <td>${escapeHtml(e.actor || "—")}</td>
      <td>${escapeHtml(e.event_type)}</td>
      <td>${escapeHtml(e.method || "")}</td>
      <td class="mono">${escapeHtml((e.path || "").slice(0, 50))}</td>
      <td class="${statusClass(e.response_status)}">${e.response_status ?? "—"}</td>
      <td style="cursor:pointer" title="click to verify" onclick="verifyTimestamp(${e.id})">${tsCell(e)}</td>
      <td class="mono" title="${escapeHtml(e.this_hash)}">${escapeHtml(e.this_hash?.slice(0, 12))}…</td>
    </tr>`;
  }
  html += "</tbody></table>";
  list.innerHTML = html;
}

function tsCell(e) {
  if (!e.ts_provider) return '<span style="color:#8a93a6">—</span>';
  if (e.ts_qualified)
    return `<span style="color:#1f9d57" title="eIDAS qualified (${escapeHtml(e.ts_provider)})">🛡 eIDAS</span>`;
  return `<span style="color:#8aa0b8" title="local signed timestamp (${escapeHtml(e.ts_provider)})">🕒 local</span>`;
}

async function verifyTimestamp(id) {
  try {
    const r = await fetch(`/_immutrace/audit/events/${id}/verify-timestamp`,
      { method: "POST", credentials: "same-origin" });
    const j = await r.json();
    if (j.ok) {
      alert(`Timestamp VALID\nprovider: ${j.provider}\nqualified (eIDAS): ${j.is_qualified}\ntime: ${j.timestamp_iso}`);
    } else {
      alert(`Timestamp: ${j.status || j.error || "no timestamp for this event"}`);
    }
  } catch (e) { alert("Error: " + e.message); }
}
window.verifyTimestamp = verifyTimestamp;

async function loadAnchors() {
  const data = await api("/_immutrace/audit/anchors");
  const list = $("#anchors-list");
  if (!data.anchors.length) {
    list.innerHTML = '<p class="muted">No anchors yet. Generate some events first, then click ⚓ Anchor pending.</p>';
    return;
  }
  list.innerHTML = "";
  for (const a of data.anchors) {
    const card = document.createElement("div");
    card.className = "anchor-card";
    const polygonscan = a.chain === "polygon-amoy"
      ? `<a href="https://amoy.polygonscan.com/tx/${a.tx_hash}" target="_blank">Polygonscan ↗</a>`
      : `<span class="muted">(mock — no on-chain tx)</span>`;
    card.innerHTML = `
      <div>
        <div class="label">Anchor #${a.id} · ${escapeHtml(a.chain)}</div>
        <div class="val">${a.event_count} events · ids ${a.first_event_id}–${a.last_event_id}</div>
        <div class="label" style="margin-top:8px;">Submitted</div>
        <div class="val">${fmtTs(a.submitted_at)}</div>
      </div>
      <div>
        <div class="label">Merkle root</div>
        <div class="val">${escapeHtml(a.merkle_root)}</div>
      </div>
      <div>
        <div class="label">Tx hash · block ${a.block_number ?? "—"}</div>
        <div class="val">${escapeHtml(a.tx_hash || "—")}</div>
        <div style="margin-top:6px;">${polygonscan}</div>
      </div>
    `;
    list.appendChild(card);
  }
}

async function verifyChain(sessionId) {
  const dlg = $("#verify-dialog");
  const body = $("#verify-body");
  body.innerHTML = '<p class="muted">Verifying…</p>';
  dlg.showModal();
  try {
    const r = await api(`/_immutrace/audit/verify/${sessionId}`);
    if (r.ok) {
      body.innerHTML = `
        <div class="verify-ok">✓ INTEGRITY VERIFIED</div>
        <p>The hash chain for session <b>${escapeHtml(sessionId)}</b> is intact.</p>
        <div class="verify-detail">Events checked: ${r.count}</div>`;
    } else {
      body.innerHTML = `
        <div class="verify-fail">✗ CHAIN BROKEN</div>
        <p>Tampering detected at event index <b>${r.broken_at}</b>.</p>
        <div class="verify-detail">Of ${r.count} events, the chain breaks at index ${r.broken_at} (1-based: event #${r.broken_at + 1}).</div>`;
    }
  } catch (e) {
    body.innerHTML = `<div class="verify-fail">Error</div><div class="verify-detail">${escapeHtml(e.message)}</div>`;
  }
}
window.verifyChain = verifyChain;

function showEvents(sessionId) {
  $("#filter-session").value = sessionId;
  switchTab("events");
  loadEvents(sessionId);
}
window.showEvents = showEvents;

function switchTab(name) {
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  $$(".tab-panel").forEach(p => p.classList.toggle("active", p.id === `tab-${name}`));
  if (name === "sessions") loadSessions();
  if (name === "events") loadEvents();
  if (name === "anchors") loadAnchors();
}

document.addEventListener("DOMContentLoaded", () => {
  $$(".tab").forEach(t => t.addEventListener("click", () => switchTab(t.dataset.tab)));
  $("#refresh").addEventListener("click", () => switchTab(
    $$(".tab").find(t => t.classList.contains("active")).dataset.tab));
  $("#anchor-now").addEventListener("click", async () => {
    try {
      const r = await fetch("/_immutrace/audit/anchor-now",
        { method: "POST", credentials: "same-origin" });
      const j = await r.json();
      if (j.ok) {
        alert(`Anchored ${j.anchor.event_count} events. Tx: ${j.anchor.tx_hash.slice(0, 16)}…`);
        loadAnchors();
      } else {
        alert(j.message || "No pending events");
      }
    } catch (e) { alert("Error: " + e.message); }
  });
  $("#apply-filter").addEventListener("click", () => {
    loadEvents($("#filter-session").value.trim() || null,
               $("#filter-case").value.trim() || null,
               $("#filter-actor").value.trim() || null,
               $("#filter-risk").value || null,
               $("#filter-from").value.trim() || null,
               $("#filter-to").value.trim() || null);
  });
  $("#clear-filter").addEventListener("click", () => {
    ["#filter-session", "#filter-case", "#filter-actor", "#filter-from", "#filter-to"]
      .forEach(s => { $(s).value = ""; });
    $("#filter-risk").value = "";
    loadEvents();
  });
  switchTab("sessions");
  // Auto refresh sessions every 8s
  setInterval(() => {
    const active = $$(".tab").find(t => t.classList.contains("active"));
    if (active) switchTab(active.dataset.tab);
  }, 8000);
});
