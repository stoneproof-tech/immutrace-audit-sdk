/* IMMUTRACE Audit SDK — injected into every OSIRIS HTML response.
   Renders an authorization modal before sensitive API calls and shows
   a persistent session banner.
   AGPL-3.0 */
(function () {
  if (window.__IMMUTRACE_SDK__) return;
  window.__IMMUTRACE_SDK__ = true;

  const STYLE = `
  .imt-overlay { position: fixed; inset: 0; background: rgba(8, 12, 28, 0.78);
    z-index: 2147483647; display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  .imt-modal { background: #0e1a36; color: #e6edf7; max-width: 560px; width: 92vw;
    border: 1px solid #233a6f; border-radius: 12px; box-shadow: 0 24px 80px rgba(0,0,0,0.6);
    padding: 28px 30px; }
  .imt-modal h2 { margin: 0 0 4px; font-size: 18px; letter-spacing: 0.02em;
    color: #ffd86b; display: flex; align-items: center; gap: 10px; }
  .imt-modal h2 .imt-shield { display: inline-block; width: 18px; height: 18px;
    background: #ffd86b; clip-path: polygon(50% 0, 100% 25%, 100% 70%, 50% 100%, 0 70%, 0 25%);
    transform: translateY(1px); }
  .imt-modal .imt-sub { color: #98a8c5; font-size: 12px; margin-bottom: 18px; }
  .imt-modal label { display: block; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.1em; color: #98a8c5; margin: 12px 0 4px; }
  .imt-modal input, .imt-modal select, .imt-modal textarea {
    width: 100%; box-sizing: border-box; background: #0a142a; color: #e6edf7;
    border: 1px solid #233a6f; border-radius: 6px; padding: 8px 10px;
    font-family: inherit; font-size: 13px; }
  .imt-modal textarea { min-height: 70px; resize: vertical; }
  .imt-modal .imt-row { display: flex; gap: 10px; }
  .imt-modal .imt-row > * { flex: 1; }
  .imt-modal .imt-actions { margin-top: 18px; display: flex; gap: 10px;
    justify-content: flex-end; }
  .imt-btn { background: #ffd86b; color: #0a142a; border: 0; padding: 9px 16px;
    border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 13px; }
  .imt-btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .imt-btn-secondary { background: transparent; color: #98a8c5; border: 1px solid #233a6f; }
  .imt-error { color: #ff8b8b; font-size: 12px; margin-top: 8px; }
  .imt-counter { color: #98a8c5; font-size: 10px; margin-top: 2px; }
  .imt-banner { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483646;
    background: linear-gradient(90deg, #16243f, #0e1a36); color: #ffd86b;
    border-bottom: 1px solid #233a6f; padding: 6px 14px;
    font: 600 11px/1 -apple-system, "Segoe UI", sans-serif;
    letter-spacing: 0.08em; display: flex; align-items: center; gap: 14px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.4); }
  .imt-banner .imt-dot { width: 8px; height: 8px; border-radius: 50%;
    background: #00e3a5; box-shadow: 0 0 8px #00e3a5; animation: imt-pulse 1.8s infinite; }
  @keyframes imt-pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
  .imt-banner .imt-grow { flex: 1; }
  .imt-banner a { color: #ffd86b; text-decoration: underline; opacity: 0.85; }
  .imt-banner a:hover { opacity: 1; }
  .imt-banner button { background: transparent; color: #98a8c5; border: 1px solid #233a6f;
    border-radius: 4px; padding: 3px 8px; font-size: 10px; cursor: pointer; }
  body { padding-top: 28px !important; }
  `;

  const $ = (tag, attrs = {}, ...children) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "style") Object.assign(el.style, v);
      else if (k === "on") for (const [evt, fn] of Object.entries(v)) el.addEventListener(evt, fn);
      else el.setAttribute(k, v);
    }
    for (const c of children) el.append(c?.nodeType ? c : document.createTextNode(c ?? ""));
    return el;
  };

  function injectStyle() {
    if (document.getElementById("imt-style")) return;
    const s = document.createElement("style");
    s.id = "imt-style";
    s.textContent = STYLE;
    document.head.appendChild(s);
  }

  let currentSession = null;
  let pendingResolvers = [];

  async function loadSession() {
    try {
      const r = await window.__imt_orig_fetch("/_immutrace/session/current",
        { credentials: "same-origin" });
      const j = await r.json();
      if (j.active) currentSession = j;
      else currentSession = null;
    } catch (e) {
      currentSession = null;
    }
    return currentSession;
  }

  // ── Identity (Step 2: multi-user login) ──
  let currentUser = null;

  async function loadAuth() {
    try {
      const r = await window.__imt_orig_fetch("/_immutrace/auth/me",
        { credentials: "same-origin" });
      const j = await r.json();
      currentUser = j.authenticated ? j : null;
    } catch (e) { currentUser = null; }
    return currentUser;
  }

  function renderIdentity(bannerEl) {
    if (currentUser) {
      if (currentUser.role === "supervisor" || currentUser.role === "admin") {
        bannerEl.append($("a", { href: "/_immutrace/supervisor/queue", target: "_blank" }, "Approval queue ↗"));
      }
      if (currentUser.role === "admin") {
        bannerEl.append($("a", { href: "/_immutrace/admin/keys", target: "_blank" }, "Key custody ↗"));
      }
      if (currentUser.role === "custodian") {
        bannerEl.append($("a", { href: "/_immutrace/custodian/panel", target: "_blank" }, "Custodian panel ↗"));
      }
      bannerEl.append(
        $("a", { href: "/_immutrace/analyst/requests", target: "_blank" }, "My requests ↗"),
        $("span", { style: { color: "#bcd6ff", fontWeight: "600" } },
          `\u{1F464} ${currentUser.username} (${currentUser.role})`),
        $("button", { on: { click: async () => {
          await window.__imt_orig_fetch("/_immutrace/auth/logout",
            { method: "POST", credentials: "same-origin" });
          location.reload();
        }}}, "Logout"),
      );
    } else {
      bannerEl.append($("button", { on: { click: () => showLoginModal() } }, "Login"));
    }
  }

  function showLoginModal() {
    // Only one login modal at a time (multiple sensitive 401s would otherwise stack it).
    if (document.querySelector(".imt-login-overlay")) return;
    injectStyle();
    const overlay = $("div", { class: "imt-overlay imt-login-overlay" });
    const modal = $("div", { class: "imt-modal" });
    const heading = $("h2", {}, $("span", { class: "imt-shield" }), "Sign in to IMMUTRACE");
    const sub = $("p", { class: "imt-sub" }, "Authenticate with your IMMUTRACE account.");
    const inUser = $("input", { type: "text", placeholder: "username",
      value: localStorage.getItem("imt:lastUser") || "" });
    const inPass = $("input", { type: "password", placeholder: "password" });
    const err = $("div", { class: "imt-error" });
    const btn = $("button", { class: "imt-btn" }, "Sign in");
    btn.addEventListener("click", async () => {
      err.textContent = ""; btn.disabled = true;
      try {
        const r = await window.__imt_orig_fetch("/_immutrace/auth/login", {
          method: "POST", headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ username: inUser.value.trim(), password: inPass.value }),
        });
        if (!r.ok) throw new Error(r.status === 401 ? "Invalid credentials" : "Login failed");
        localStorage.setItem("imt:lastUser", inUser.value.trim());
        location.reload();
      } catch (e) { err.textContent = e.message; btn.disabled = false; }
    });
    inPass.addEventListener("keydown", (e) => { if (e.key === "Enter") btn.click(); });
    const cancel = $("button", { class: "imt-btn-secondary",
      on: { click: () => overlay.remove() } }, "Cancel");
    modal.append(heading, sub,
      $("label", {}, "Username"), inUser,
      $("label", {}, "Password"), inPass, err,
      $("div", { class: "imt-actions" }, cancel, btn));
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    setTimeout(() => inUser.focus(), 100);
  }

  // Step 3: request supervisor authorization for a blocked endpoint.
  function showRequestModal(targetPath) {
    if (document.querySelector(".imt-request-overlay")) return;  // one at a time
    injectStyle();
    const overlay = $("div", { class: "imt-overlay imt-request-overlay" });
    const modal = $("div", { class: "imt-modal" });
    const inCase = $("input", { type: "text", placeholder: "e.g. CASE-2026-0142 (optional)",
      value: localStorage.getItem("imt:lastCase") || "" });
    const inUrg = $("select");
    for (const u of ["low", "normal", "high"]) {
      const o = document.createElement("option"); o.value = o.textContent = u; inUrg.appendChild(o);
    }
    inUrg.value = "normal";
    const inJust = $("textarea", { placeholder:
      "Describe the legitimate purpose of this access (≥ 10 chars)." });
    const counter = $("div", { class: "imt-counter" }, "0 / 10 chars minimum");
    const err = $("div", { class: "imt-error" });
    const btn = $("button", { class: "imt-btn" }, "Submit request");
    btn.disabled = true;
    inJust.addEventListener("input", () => {
      const n = inJust.value.trim().length;
      counter.textContent = `${n} / 10 chars minimum`;
      btn.disabled = n < 10;
    });
    btn.addEventListener("click", async () => {
      err.textContent = ""; btn.disabled = true;
      try {
        const r = await window.__imt_orig_fetch("/_immutrace/approval/request", {
          method: "POST", headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ target_path: targetPath, justification: inJust.value.trim(),
            case_id: inCase.value.trim(), urgency: inUrg.value }),
        });
        if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.detail || "Request failed"); }
        localStorage.setItem("imt:lastCase", inCase.value.trim());
        modal.innerHTML = "";
        modal.append(
          $("h2", {}, $("span", { class: "imt-shield" }), "Request submitted"),
          $("p", { class: "imt-sub" },
            `Awaiting supervisor approval for ${targetPath}. Once approved, reload the page to gain access.`),
          $("div", { class: "imt-actions" },
            $("button", { class: "imt-btn", on: { click: () => overlay.remove() } }, "Close")),
        );
      } catch (e) { err.textContent = e.message; btn.disabled = false; }
    });
    const cancel = $("button", { class: "imt-btn-secondary", on: { click: () => overlay.remove() } }, "Cancel");
    modal.append(
      $("h2", {}, $("span", { class: "imt-shield" }), "Request authorization"),
      $("p", { class: "imt-sub" },
        `Access to ${targetPath} requires supervisor approval. Your request is chained and auditable.`),
      $("label", {}, "Justification (≥ 10 chars)"), inJust, counter,
      $("div", { class: "imt-row" },
        $("div", {}, $("label", {}, "Urgency"), inUrg),
        $("div", {}, $("label", {}, "Case ID (optional)"), inCase)),
      err, $("div", { class: "imt-actions" }, cancel, btn));
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    setTimeout(() => inJust.focus(), 100);
  }

  function showBanner() {
    let b = document.getElementById("imt-banner");
    if (currentSession) {
      if (!b) {
        b = $("div", { id: "imt-banner", class: "imt-banner" });
        document.body.appendChild(b);
      }
      const caseTxt = currentSession.case_id
        ? ` · case ${currentSession.case_id}` : "";
      b.innerHTML = "";
      b.append(
        $("span", { class: "imt-dot" }),
        $("span", {}, "IMMUTRACE AUDIT ACTIVE"),
        $("span", { style: { color: "#98a8c5", fontWeight: "400" } },
          `${currentSession.actor} · ${currentSession.activity_type}${caseTxt}`),
        $("span", { class: "imt-grow" }),
        $("a", { href: "/_immutrace/dashboard", target: "_blank" }, "View dashboard ↗"),
        $("button", {
          on: { click: async () => {
            await window.__imt_orig_fetch("/_immutrace/session/end",
              { method: "POST", credentials: "same-origin" });
            currentSession = null;
            b.remove();
            document.body.style.paddingTop = "";
          }}
        }, "End session"),
      );
      renderIdentity(b);
    } else if (b) {
      b.remove();
      document.body.style.paddingTop = "";
    }
  }

  function showModal({ reason } = {}) {
    injectStyle();
    return new Promise((resolve) => {
      const overlay = $("div", { class: "imt-overlay" });
      const modal = $("div", { class: "imt-modal" });

      const heading = $("h2", {}, $("span", { class: "imt-shield" }), "Investigation authorization required");
      const sub = $("p", { class: "imt-sub" },
        reason ||
        "An IMMUTRACE investigation session is required before accessing intelligence data. " +
        "Your justification will be permanently chained and anchored on-chain.");

      const inActor = $("input", { type: "text", placeholder: "your.name@authority.gov",
        value: localStorage.getItem("imt:lastActor") || "" });
      const inCase = $("input", { type: "text", placeholder: "e.g. CASE-2026-0142 (optional)",
        value: localStorage.getItem("imt:lastCase") || "" });
      const inType = $("select");
      for (const opt of ["OSINT_RESEARCH", "INVESTIGATION", "ROUTINE_MONITORING"]) {
        const o = document.createElement("option");
        o.value = o.textContent = opt;
        inType.appendChild(o);
      }
      inType.value = localStorage.getItem("imt:lastType") || "OSINT_RESEARCH";

      const inJust = $("textarea", { placeholder:
        "Describe the legitimate purpose of this access (≥ 20 chars). E.g. 'Routine maritime traffic review for case 2026-0142 — sanctions enforcement Red Sea.'" });
      const counter = $("div", { class: "imt-counter" }, "0 / 20 chars minimum");
      const err = $("div", { class: "imt-error" });
      const btn = $("button", { class: "imt-btn" }, "Authorize & start session");
      btn.disabled = true;

      inJust.addEventListener("input", () => {
        const len = inJust.value.trim().length;
        counter.textContent = `${len} / 20 chars minimum`;
        btn.disabled = len < 20 || !inActor.value.trim();
      });
      inActor.addEventListener("input", () => {
        const len = inJust.value.trim().length;
        btn.disabled = len < 20 || !inActor.value.trim();
      });

      btn.addEventListener("click", async () => {
        err.textContent = "";
        btn.disabled = true;
        try {
          const r = await window.__imt_orig_fetch("/_immutrace/session/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({
              actor: inActor.value.trim(),
              case_id: inCase.value.trim(),
              activity_type: inType.value,
              justification: inJust.value.trim(),
            }),
          });
          if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.detail || "Session creation failed");
          }
          const j = await r.json();
          currentSession = {
            active: true, session_id: j.session_id, actor: j.actor,
            case_id: j.case_id, activity_type: j.activity_type,
            justification: inJust.value.trim(), expires_at: j.expires_at,
          };
          localStorage.setItem("imt:lastActor", inActor.value.trim());
          localStorage.setItem("imt:lastCase", inCase.value.trim());
          localStorage.setItem("imt:lastType", inType.value);
          overlay.remove();
          showBanner();
          // Resolve all waiters
          for (const r of pendingResolvers) r(true);
          pendingResolvers = [];
          resolve(true);
        } catch (e) {
          err.textContent = e.message;
          btn.disabled = false;
        }
      });

      modal.append(
        heading, sub,
        $("label", {}, "Investigator"), inActor,
        $("div", { class: "imt-row" },
          $("div", {},
            $("label", {}, "Activity type"), inType,
          ),
          $("div", {},
            $("label", {}, "Case ID (optional)"), inCase,
          ),
        ),
        $("label", {}, "Justification (≥ 20 chars)"), inJust, counter,
        err,
        $("div", { class: "imt-actions" }, btn),
      );
      overlay.appendChild(modal);
      document.body.appendChild(overlay);
      setTimeout(() => inActor.focus(), 100);
    });
  }

  // ── fetch interceptor: catches 401 AUTH_REQUIRED responses ──
  window.__imt_orig_fetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const r = await window.__imt_orig_fetch(input, init);
    if (r.status === 401 && r.headers.get("X-Immutrace-Gate") === "blocked") {
      // Identity comes first: you must be logged in before you can be authorized.
      if (!currentUser) { await loadAuth(); }
      if (!currentUser) {
        showLoginModal();   // log in, then reload re-issues the request
        return r;
      }
      // Logged in → request supervisor approval for this endpoint (pre-auth model).
      // No automatic retry: access is granted only after a supervisor approves,
      // at which point the analyst reloads.
      const url = typeof input === "string" ? input : (input && input.url) || "";
      let path = url;
      try { path = new URL(url, location.origin).pathname; } catch (e) {}
      showRequestModal(path);
      return r;
    }
    return r;
  };

  // Boot: load current session, show banner OR prompt
  async function boot() {
    await loadSession();
    await loadAuth();
    if (currentSession) {
      showBanner();
    } else {
      // Don't force the modal on initial page load (let analyst browse static
      // shell first). The modal appears the moment a sensitive fetch returns 401.
      // But surface a tiny indicator that audit is OFF.
      const off = $("div", { id: "imt-banner", class: "imt-banner",
        style: { background: "linear-gradient(90deg, #3a1414, #2a0e0e)",
                 color: "#ffb4b4", borderColor: "#5a2424" } });
      const msg = currentUser
        ? "Sensitive endpoints require supervisor approval"
        : "Log in to access — sensitive endpoints require approval";
      off.append(
        $("span", { class: "imt-dot", style: { background: "#ff5a5a", boxShadow: "0 0 8px #ff5a5a" } }),
        $("span", {}, "IMMUTRACE AUDIT — NO ACTIVE AUTHORIZATION"),
        $("span", { style: { color: "#98a8c5", fontWeight: "400" } }, msg),
        $("span", { class: "imt-grow" }),
        $("a", { href: "/_immutrace/dashboard", target: "_blank" }, "Dashboard ↗"),
      );
      renderIdentity(off);
      document.body.appendChild(off);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
