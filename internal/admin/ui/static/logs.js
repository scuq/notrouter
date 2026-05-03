// logs.js - tail of slog ring buffer with sane scroll behavior.
//
// Three states that the UI moves between:
//   tailing  - viewport is at-or-near bottom, auto-scrolls on new lines
//   paused   - user scrolled up; new lines append silently, banner counts
//   resuming - one-shot snap-to-bottom, returns to tailing
//
// The trick is distinguishing "user scrolled" from "code scrolled to
// bottom". We do this with a programmaticScroll flag that's true only
// during our own scrollTop assignment. The 'scroll' event fires async,
// so we clear the flag on the next animation frame.
(function () {
  const POLL_MS = 1000;
  const NEAR_BOTTOM_PX = 30; // within this distance = "at bottom"
  const MAX_DOM_LINES = 5000; // hard cap to prevent runaway memory

  const $list = document.getElementById("log-list");
  const $container = document.getElementById("log-container");
  const $resume = document.getElementById("log-resume");
  const $resumeCount = document.getElementById("log-resume-count");
  const $status = document.getElementById("log-status");
  const $level = document.getElementById("log-level");
  const $search = document.getElementById("log-search");
  const $clear = document.getElementById("log-clear");

  let lastSeq = 0;        // highest seq we've rendered
  let paused = false;     // true when user has scrolled up
  let pendingNew = 0;     // count of lines appended while paused
  let programmaticScroll = false;
  let pollTimer = null;
  let inflight = false;

  function isAtBottom() {
    const distance = $container.scrollHeight - $container.scrollTop - $container.clientHeight;
    return distance <= NEAR_BOTTOM_PX;
  }

  function snapToBottom() {
    programmaticScroll = true;
    $container.scrollTop = $container.scrollHeight;
    // Clear the flag after the resulting scroll event has fired. rAF
    // schedules for the next frame, by which point the event has bubbled.
    requestAnimationFrame(() => { programmaticScroll = false; });
  }

  function setPaused(v) {
    if (v === paused) return;
    paused = v;
    if (paused) {
      $resume.style.display = "block";
      $status.textContent = "paused";
    } else {
      $resume.style.display = "none";
      $status.textContent = "tailing";
      pendingNew = 0;
    }
  }

  $container.addEventListener("scroll", () => {
    if (programmaticScroll) return;
    // User-initiated scroll. Are we still at bottom?
    if (isAtBottom()) {
      setPaused(false);
    } else {
      setPaused(true);
    }
  });

  $resume.addEventListener("click", () => {
    setPaused(false);
    snapToBottom();
  });

  $level.addEventListener("change", reset);
  $search.addEventListener("input", debounce(reset, 200));
  $clear.addEventListener("click", () => {
    $list.innerHTML = "";
    // Don't reset lastSeq - we want to skip already-fetched lines, not
    // re-fetch them. Clear is purely visual.
  });

  function reset() {
    // Filter changed; wipe view and refetch from current high water mark.
    // We don't go back to seq=0 because that could be 1000 lines all at
    // once; users want "new traffic matching this filter" semantics.
    lastSeq = 0;
    $list.innerHTML = "";
    setPaused(false);
    pendingNew = 0;
    fetchLogs(true);
  }

  function debounce(fn, ms) {
    let t = null;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  }

  async function fetchLogs(initial) {
    if (inflight) return;
    inflight = true;
    try {
      const params = new URLSearchParams({
        since: String(lastSeq),
        level: $level.value,
        search: $search.value,
      });
      const r = await fetch("/admin/api/logs?" + params, { credentials: "same-origin" });
      if (r.status === 401) {
        window.location.href = "/admin/ui/login";
        return;
      }
      if (!r.ok) throw new Error("http " + r.status);
      const data = await r.json();
      const entries = data.entries || [];
      if (entries.length === 0) return;

      // On the very first poll we want to show the existing buffered lines,
      // but on subsequent polls we already have history - only append new.
      const wasAtBottom = isAtBottom();

      const frag = document.createDocumentFragment();
      for (const e of entries) {
        if (e.seq > lastSeq) lastSeq = e.seq;
        frag.appendChild(renderLine(e));
      }
      $list.appendChild(frag);

      // Cap DOM size: oldest go first.
      while ($list.childElementCount > MAX_DOM_LINES) {
        $list.removeChild($list.firstChild);
      }

      if (paused) {
        pendingNew += entries.length;
        $resumeCount.textContent = pendingNew + " new line" + (pendingNew === 1 ? "" : "s");
      } else if (wasAtBottom || initial) {
        snapToBottom();
      }
    } catch (e) {
      $status.textContent = "error: " + e.message;
    } finally {
      inflight = false;
    }
  }

  function renderLine(e) {
    const div = document.createElement("div");
    div.className = "log-line lvl-" + (e.level || "INFO").toLowerCase();
    const time = (e.time || "").replace("T", " ").substring(11, 23);
    const lvl = (e.level || "INFO").toUpperCase().padEnd(5);
    let attrs = "";
    if (e.attrs) {
      const keys = Object.keys(e.attrs);
      if (keys.length > 0) {
        attrs = " " + keys.map(k => k + "=" + e.attrs[k]).join(" ");
      }
    }
    // textContent for safety - log content can include user-controlled
    // strings (entity names, payload bodies) and we won't trust them.
    const t = document.createElement("span");
    t.className = "log-time";
    t.textContent = time;
    const l = document.createElement("span");
    l.className = "log-level";
    l.textContent = lvl;
    const m = document.createElement("span");
    m.className = "log-msg";
    m.textContent = " " + e.msg + attrs;
    div.appendChild(t);
    div.appendChild(document.createTextNode(" "));
    div.appendChild(l);
    div.appendChild(m);
    return div;
  }

  // Kickoff
  fetchLogs(true);
  pollTimer = setInterval(fetchLogs, POLL_MS);
})();
