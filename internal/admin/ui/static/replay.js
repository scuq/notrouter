// replay.js - drives the /admin/ui/replay page.
//
// Two API calls used:
//   GET  /admin/api/audit/recent?limit=50&filter=...
//   POST /admin/api/routing/analyze  body={"audit_id":"..."}
//
// Vanilla JS, no framework. Same style as the rest of /admin/ui.

(function () {
  const listEl = document.getElementById('replay-list');
  const resultsEl = document.getElementById('replay-results');
  const filterEl = document.getElementById('replay-filter');
  const countEl = document.getElementById('replay-count');
  const refreshBtn = document.getElementById('replay-refresh');

  let currentEntries = [];
  let selectedId = null;

  // ---------- audit list ----------

  async function loadAudit() {
    listEl.innerHTML = '<div class="replay-empty">loading...</div>';
    const filter = filterEl.value.trim();
    const url = '/admin/api/audit/recent?limit=50' +
      (filter ? '&filter=' + encodeURIComponent(filter) : '');
    try {
      const res = await fetch(url, { credentials: 'same-origin' });
      if (!res.ok) {
        listEl.innerHTML = '<div class="replay-error">load failed: HTTP ' + res.status + '</div>';
        return;
      }
      const data = await res.json();
      currentEntries = data.entries || [];
      renderList();
      countEl.textContent = '(' + (data.count || 0) + ' shown)';
    } catch (e) {
      listEl.innerHTML = '<div class="replay-error">load failed: ' + e.message + '</div>';
    }
  }

  function renderList() {
    if (currentEntries.length === 0) {
      listEl.innerHTML = '<div class="replay-empty">no events match. enable trace + send some events to populate the audit log.</div>';
      return;
    }
    listEl.innerHTML = '';
    for (const e of currentEntries) {
      const id = e.id || '';
      const ts = e.timestamp || '';
      const topic = e.topic || '(no topic)';
      const entity = e.entity || '(no entity)';
      const source = e.source || '';
      const tsShort = ts ? ts.slice(11, 19) : '?';

      const div = document.createElement('div');
      div.className = 'replay-row' + (id === selectedId ? ' selected' : '');
      div.dataset.auditId = id;
      div.innerHTML =
        '<div><span class="ts">' + escapeHtml(tsShort) + '</span> ' +
        '<span class="topic">' + escapeHtml(topic) + '</span></div>' +
        '<div><span class="entity">' + escapeHtml(entity) + '</span>' +
        ' <span class="ts">' + escapeHtml(source) + '</span></div>';
      div.addEventListener('click', () => selectEvent(id));
      listEl.appendChild(div);
    }
  }

  // ---------- analysis ----------

  async function selectEvent(id) {
    selectedId = id;
    // Update visual selection
    document.querySelectorAll('.replay-row').forEach(r => {
      r.classList.toggle('selected', r.dataset.auditId === id);
    });
    if (!id) {
      resultsEl.innerHTML = '<div class="replay-empty">select an event from the list to analyze it</div>';
      return;
    }
    resultsEl.innerHTML = '<div class="replay-empty">analyzing...</div>';
    try {
      const res = await fetch('/admin/api/routing/analyze', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ audit_id: id }),
      });
      if (!res.ok) {
        const txt = await res.text();
        resultsEl.innerHTML = '<div class="replay-error">analyze failed: HTTP ' +
          res.status + '<br><pre>' + escapeHtml(txt) + '</pre></div>';
        return;
      }
      const data = await res.json();
      renderResults(data);
    } catch (e) {
      resultsEl.innerHTML = '<div class="replay-error">analyze error: ' + escapeHtml(e.message) + '</div>';
    }
  }

  function renderResults(r) {
    const ev = r.event || {};
    let html = '<h3 style="margin-top:0">event</h3>';
    html += '<div class="replay-meta">';
    html += '<div><strong>topic:</strong> ' + escapeHtml(ev.topic || '(empty)') + '</div>';
    html += '<div><strong>entity:</strong> ' + escapeHtml(ev.entity || '(empty)') + '</div>';
    html += '<div><strong>source:</strong> ' + escapeHtml(ev.source || '') + '</div>';
    html += '<div><strong>urgency:</strong> ' + escapeHtml(ev.urgency || '') + '</div>';
    html += '</div>';

    // Suppression
    html += '<h3>suppression</h3>';
    if (r.suppression && r.suppression.suppressed) {
      html += '<div class="replay-warn">SUPPRESSED by rule #' +
        r.suppression.matched_rule_idx + ' (' +
        escapeHtml(r.suppression.matched_rule || '') + ')</div>';
    } else {
      html += '<div class="replay-meta">not suppressed</div>';
    }

    // Dedup
    html += '<h3>dedup</h3>';
    if (r.dedup) {
      html += '<div class="replay-meta">key: <code>' + escapeHtml(r.dedup.key || '') + '</code></div>';
      if (r.dedup.would_be_deduped) {
        const lastSeen = r.dedup.last_seen_at ? r.dedup.last_seen_at.slice(0, 19).replace('T', ' ') : '';
        html += '<div class="replay-warn">WOULD BE DEDUPED (last seen at ' + escapeHtml(lastSeen) + ')</div>';
      } else {
        html += '<div class="replay-meta">would NOT be deduped (key not in cache or expired)</div>';
      }
    }

    // Routing
    html += '<h3>routing</h3>';
    const rules = (r.routing && r.routing.rules) || [];
    if (rules.length === 0) {
      html += '<div class="replay-empty">no routing rules configured</div>';
    } else {
      for (const rule of rules) {
        const cls = rule.matched ? 'matched' : 'unmatched';
        const marker = rule.matched ? '✓' : '✗';
        const groupsAdded = (rule.groups_added || []).join(', ');
        html += '<div class="replay-rule ' + cls + '">' +
          '<span class="replay-rule-marker">' + marker + '</span>' +
          '<strong>rule #' + rule.index + ':</strong> ' + escapeHtml(rule.description || '');
        if (rule.matched && groupsAdded) {
          html += '<div style="margin-left:18px;">→ groups: ' + escapeHtml(groupsAdded) + '</div>';
        }
        html += '</div>';
      }
    }

    // Resolved groups -> subscribers
    const groupsResolved = (r.routing && r.routing.groups_resolved) || {};
    const groupNames = Object.keys(groupsResolved);
    if (groupNames.length > 0) {
      html += '<h3>group expansion</h3>';
      for (const gn of groupNames) {
        const subs = (groupsResolved[gn] || []).join(', ');
        html += '<div class="replay-meta">' + escapeHtml(gn) + ': ' + escapeHtml(subs || '(empty)') + '</div>';
      }
    }

    // Final
    html += '<h3>final subscribers</h3>';
    const finals = r.final_subscribers || [];
    if (finals.length === 0) {
      html += '<div class="replay-warn">NONE - event would not be delivered (suppressed, deduped, or no matching routing rule)</div>';
    } else {
      html += '<div class="replay-subscribers">' + escapeHtml(finals.join(', ')) + '</div>';
    }

    resultsEl.innerHTML = html;
  }

  // ---------- helpers ----------

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ---------- event handlers ----------

  refreshBtn.addEventListener('click', loadAudit);
  filterEl.addEventListener('input', debounce(loadAudit, 300));

  function debounce(fn, ms) {
    let t = null;
    return function () {
      if (t) clearTimeout(t);
      t = setTimeout(fn, ms);
    };
  }

  // ---------- bootstrap ----------

  loadAudit();
})();
