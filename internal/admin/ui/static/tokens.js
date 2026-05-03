// tokens.js - mint, list, refresh, revoke API tokens.
//
// Important UX rule: a freshly-minted token is shown ONCE in the
// "tok-fresh" panel. After dismiss, that plaintext is gone forever
// because the server only stored its hash. The revoke + re-mint flow
// is the recovery path if a user fails to copy.
(function () {
  const $label = document.getElementById("tok-label");
  const $mint = document.getElementById("tok-mint");
  const $status = document.getElementById("tok-status");
  const $fresh = document.getElementById("tok-fresh");
  const $freshCode = document.getElementById("tok-fresh-code");
  const $copy = document.getElementById("tok-copy");
  const $dismiss = document.getElementById("tok-dismiss");
  const $tbody = document.getElementById("tok-tbody");

  if (!$label) return;

  function getCookie(name) {
    const m = document.cookie.match(
      new RegExp("(^|; )" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]*)")
    );
    return m ? decodeURIComponent(m[2]) : "";
  }

  function setStatus(kind, text) {
    $status.className = "cfg-status " + kind;
    $status.textContent = text;
  }

  async function api(method, url, body) {
    const opts = {
      method: method,
      credentials: "same-origin",
      headers: {
        "X-CSRF-Token": getCookie("notrouter_csrf"),
      },
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(url, opts);
    let data = null;
    try { data = await r.json(); } catch (e) { /* non-json */ }
    return { status: r.status, data };
  }

  async function refreshList() {
    const { status, data } = await api("GET", "/admin/api/tokens");
    if (status !== 200) {
      $tbody.innerHTML = '<tr><td colspan="5" style="color:#ff5570">error: HTTP ' + status + '</td></tr>';
      return;
    }
    const tokens = (data && data.tokens) || [];
    if (tokens.length === 0) {
      $tbody.innerHTML = '<tr><td colspan="5" style="color:#1ea53a">no tokens yet - create one above</td></tr>';
      return;
    }
    $tbody.innerHTML = "";
    for (const t of tokens) {
      $tbody.appendChild(renderRow(t));
    }
  }

  function renderRow(t) {
    const tr = document.createElement("tr");
    if (t.expired) tr.classList.add("expired");
    const td = (text) => {
      const c = document.createElement("td");
      c.textContent = text;
      return c;
    };
    tr.appendChild(td(t.label || "(unlabeled)"));
    tr.appendChild(td(formatDate(t.created_at)));

    // expires column gets relative time too
    const expiresCell = document.createElement("td");
    if (t.expired) {
      expiresCell.innerHTML = '<span style="color:#ff5570">EXPIRED</span> ' + formatDate(t.expires_at);
    } else {
      expiresCell.textContent = formatDate(t.expires_at) + " (" + relTime(t.expires_at) + ")";
    }
    tr.appendChild(expiresCell);

    tr.appendChild(td(t.last_used_at && t.last_used_at !== "0001-01-01T00:00:00Z" ? formatDate(t.last_used_at) : "never"));

    const actions = document.createElement("td");
    if (!t.expired) {
      const r = document.createElement("button");
      r.textContent = "refresh";
      r.className = "inline-btn small";
      r.addEventListener("click", () => refreshToken(t.hash));
      actions.appendChild(r);
    }
    const x = document.createElement("button");
    x.textContent = "revoke";
    x.className = "inline-btn small danger";
    x.addEventListener("click", () => revokeToken(t.hash, t.label));
    actions.appendChild(x);
    tr.appendChild(actions);
    return tr;
  }

  function formatDate(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    return d.getFullYear() + "-"
      + String(d.getMonth() + 1).padStart(2, "0") + "-"
      + String(d.getDate()).padStart(2, "0") + " "
      + String(d.getHours()).padStart(2, "0") + ":"
      + String(d.getMinutes()).padStart(2, "0");
  }

  function relTime(iso) {
    const target = new Date(iso).getTime();
    const now = Date.now();
    const diff = target - now;
    if (diff < 0) return "expired";
    const days = Math.floor(diff / (24 * 3600 * 1000));
    if (days >= 1) return days + "d";
    const hours = Math.floor(diff / (3600 * 1000));
    if (hours >= 1) return hours + "h";
    const mins = Math.floor(diff / (60 * 1000));
    return mins + "m";
  }

  $mint.addEventListener("click", async () => {
    const label = $label.value.trim();
    if (label.length < 3) {
      setStatus("error", "label must be at least 3 characters");
      return;
    }
    setStatus("info", "minting_");
    const { status, data } = await api("POST", "/admin/api/tokens/mint", { label });
    if (status !== 200) {
      setStatus("error", "mint failed: " + (data && data.error || "HTTP " + status));
      return;
    }
    setStatus("ok", "token created - SAVE IT NOW (only shown once)");
    $freshCode.textContent = data.token;
    $fresh.style.display = "block";
    $label.value = "";
    refreshList();
  });

  $copy.addEventListener("click", async () => {
    const text = $freshCode.textContent;
    try {
      await navigator.clipboard.writeText(text);
      $copy.textContent = "copied!";
      setTimeout(() => { $copy.textContent = "copy to clipboard"; }, 2000);
    } catch (e) {
      // Clipboard API can fail on insecure origins or in restricted
      // browser contexts. Fallback: select the code element so user
      // can ctrl+c.
      const range = document.createRange();
      range.selectNodeContents($freshCode);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      setStatus("info", "clipboard API unavailable - text is selected, use Ctrl+C");
    }
  });

  $dismiss.addEventListener("click", () => {
    $freshCode.textContent = "";
    $fresh.style.display = "none";
    setStatus("", "");
  });

  async function refreshToken(hash) {
    setStatus("info", "refreshing_");
    const { status, data } = await api("POST", "/admin/api/tokens/refresh", { hash });
    if (status !== 200) {
      setStatus("error", "refresh failed: " + (data && data.error || "HTTP " + status));
      return;
    }
    setStatus("ok", "extended to " + formatDate(data.view.expires_at));
    refreshList();
  }

  async function revokeToken(hash, label) {
    if (!confirm('Revoke token "' + (label || hash) + '"? This cannot be undone.')) return;
    setStatus("info", "revoking_");
    const { status, data } = await api("POST", "/admin/api/tokens/revoke", { hash });
    if (status !== 200) {
      setStatus("error", "revoke failed: " + (data && data.error || "HTTP " + status));
      return;
    }
    setStatus("ok", "revoked");
    refreshList();
  }

  refreshList();
})();
