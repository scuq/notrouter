// webhook_keys.js - mint, list, revoke webhook ingest keys.
//
// Notably similar to tokens.js but without the refresh action - webhook
// keys don't expire, they just live until revoked. The "last used"
// column matters most here since dead keys (sender went away, label is
// stale) accumulate otherwise.
(function () {
  const $label = document.getElementById("wk-label");
  const $mint = document.getElementById("wk-mint");
  const $status = document.getElementById("wk-status");
  const $fresh = document.getElementById("wk-fresh");
  const $freshCode = document.getElementById("wk-fresh-code");
  const $copy = document.getElementById("wk-copy");
  const $dismiss = document.getElementById("wk-dismiss");
  const $tbody = document.getElementById("wk-tbody");

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
      headers: { "X-CSRF-Token": getCookie("notrouter_csrf") },
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
    const { status, data } = await api("GET", "/admin/api/webhook-keys");
    if (status !== 200) {
      $tbody.innerHTML = '<tr><td colspan="5" style="color:#ff5570">error: HTTP ' + status + '</td></tr>';
      return;
    }
    const keys = (data && data.keys) || [];
    if (keys.length === 0) {
      $tbody.innerHTML = '<tr><td colspan="5" style="color:#1ea53a">no webhook keys yet - create one above to enable webhook auth</td></tr>';
      return;
    }
    $tbody.innerHTML = "";
    for (const k of keys) {
      $tbody.appendChild(renderRow(k));
    }
  }

  function renderRow(k) {
    const tr = document.createElement("tr");
    const td = (text) => {
      const c = document.createElement("td");
      c.textContent = text;
      return c;
    };
    tr.appendChild(td(k.label || "(unlabeled)"));
    tr.appendChild(td(k.created_by || "-"));
    tr.appendChild(td(formatDate(k.created_at)));

    // Last-used: highlight in red-ish if "never" - operator probably
    // wants to revoke unused keys for hygiene.
    const lu = document.createElement("td");
    if (!k.last_used_at || k.last_used_at === "0001-01-01T00:00:00Z") {
      lu.innerHTML = '<span style="color:#ff5570">never used</span>';
    } else {
      lu.textContent = formatDate(k.last_used_at) + " (" + relTimePast(k.last_used_at) + ")";
    }
    tr.appendChild(lu);

    const actions = document.createElement("td");
    const x = document.createElement("button");
    x.textContent = "revoke";
    x.className = "inline-btn small danger";
    x.addEventListener("click", () => revokeKey(k.hash, k.label));
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

  function relTimePast(iso) {
    const target = new Date(iso).getTime();
    const now = Date.now();
    const diff = now - target;
    if (diff < 0) return "in future";
    const days = Math.floor(diff / (24 * 3600 * 1000));
    if (days >= 1) return days + "d ago";
    const hours = Math.floor(diff / (3600 * 1000));
    if (hours >= 1) return hours + "h ago";
    const mins = Math.floor(diff / (60 * 1000));
    if (mins >= 1) return mins + "m ago";
    return "just now";
  }

  $mint.addEventListener("click", async () => {
    const label = $label.value.trim();
    if (label.length < 3) {
      setStatus("error", "label must be at least 3 characters");
      return;
    }
    setStatus("info", "minting_");
    const { status, data } = await api("POST", "/admin/api/webhook-keys/mint", { label });
    if (status !== 200) {
      setStatus("error", "mint failed: " + (data && data.error || "HTTP " + status));
      return;
    }
    setStatus("ok", "key created - SAVE IT NOW (only shown once)");
    $freshCode.textContent = data.key;
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

  async function revokeKey(hash, label) {
    if (!confirm(
      'Revoke webhook key "' + (label || hash) + '"?\n\n' +
      'Senders using this key will start getting 401 immediately.\n\n' +
      'This cannot be undone.'
    )) return;
    setStatus("info", "revoking_");
    const { status, data } = await api("POST", "/admin/api/webhook-keys/revoke", { hash });
    if (status !== 200) {
      setStatus("error", "revoke failed: " + (data && data.error || "HTTP " + status));
      return;
    }
    setStatus("ok", "revoked");
    refreshList();
  }

  refreshList();
})();
