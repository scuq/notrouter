// app.js - polls /admin/api/state and /admin/api/deliveries every 2s and
// re-renders the dashboard tables. No framework, no build step. The point
// is to be small enough to read in 30s.
(function () {
  const POLL_MS = 2000;

  async function fetchJSON(path) {
    const r = await fetch(path, { credentials: "same-origin" });
    if (r.status === 401) {
      // session expired - bounce to login
      window.location.href = "/admin/ui/login";
      return null;
    }
    if (!r.ok) throw new Error(path + " " + r.status);
    return r.json();
  }

  function renderQueues(queues) {
    const tbody = document.getElementById("queues-tbody");
    if (!queues || queues.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:#007a1f">no plugin instances</td></tr>';
      return;
    }
    tbody.innerHTML = queues.map(q => {
      const pct = q.capacity > 0 ? (q.depth / q.capacity * 100).toFixed(1) : "-";
      const cls = q.depth / q.capacity >= 0.9 ? "fail"
                : q.depth / q.capacity >= 0.5 ? "warn"
                : "ok";
      return `<tr>
        <td>${escapeHTML(q.instance)}</td>
        <td class="num">${q.depth}</td>
        <td class="num">${q.capacity}</td>
        <td class="num"><span class="pill ${cls}">${pct}%</span></td>
      </tr>`;
    }).join("");
  }

  function renderDeliveries(d) {
    const tbody = document.getElementById("deliveries-tbody");
    const recent = (d && d.recent) || [];
    if (recent.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:#007a1f">no deliveries yet</td></tr>';
      return;
    }
    tbody.innerHTML = recent.slice(0, 30).map(r => {
      const finalized = (r.finalized || "").replace("T", " ").substring(0, 19);
      const subList = Object.entries(r.subscribers || {})
        .map(([k, v]) => `${escapeHTML(k)}=<span class="pill ${pillFor(v)}">${escapeHTML(v)}</span>`)
        .join(" ");
      return `<tr>
        <td>${escapeHTML(finalized)}</td>
        <td><span class="pill ${pillFor(r.state)}">${escapeHTML(r.state)}</span></td>
        <td style="font-size:.75rem; color:#007a1f">${escapeHTML(r.event_id)}</td>
        <td>${subList}</td>
      </tr>`;
    }).join("");
  }

  function pillFor(state) {
    switch (state) {
      case "delivered": return "ok";
      case "failed":    return "fail";
      case "partial":   return "partial";
      case "expired":
      case "expired_partial": return "warn";
      default: return "warn";
    }
  }

  function escapeHTML(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  async function tick() {
    try {
      const [state, deliv] = await Promise.all([
        fetchJSON("/admin/api/state"),
        fetchJSON("/admin/api/deliveries"),
      ]);
      if (!state || !deliv) return;
      document.getElementById("m-dedup").textContent = state.dedup_size ?? 0;
      document.getElementById("m-pending").textContent = state.tracker_pending ?? 0;
      renderQueues(state.queues || []);
      renderDeliveries(deliv);
      document.getElementById("last-update").textContent =
        "updated " + new Date().toTimeString().substring(0, 8);
    } catch (e) {
      // Quiet on transient errors; the next tick will retry.
      document.getElementById("last-update").textContent =
        "error: " + e.message;
    }
  }

  tick();
  setInterval(tick, POLL_MS);
})();
