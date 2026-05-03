// config.js - inline YAML editor with three-button workflow:
//   VALIDATE  -> POST /admin/api/config/validate, show errors inline
//   SAVE      -> POST /admin/api/config/save (writes disk, no reload)
//   RELOAD    -> POST /admin/api/config/reload (rebuild pipeline from disk)
//
// We keep things deliberately old-school: no syntax highlighting, no
// fancy editor library. A textarea + line numbers gutter + status pane.
// The Matrix CSS sells the aesthetic.
(function () {
  const $body = document.getElementById("cfg-body");
  const $editToggle = document.getElementById("cfg-edit-toggle");
  const $validateBtn = document.getElementById("cfg-validate");
  const $saveBtn = document.getElementById("cfg-save");
  const $reloadBtn = document.getElementById("cfg-reload");
  const $status = document.getElementById("cfg-status");
  const $diskHash = document.getElementById("cfg-disk-hash");
  const $loadedHash = document.getElementById("cfg-loaded-hash");
  const $driftBanner = document.getElementById("cfg-drift");

  if (!$body) return; // defensive - wrong page

  // editing state. originalText is what we last loaded from disk; used
  // both to reset on cancel and to detect "dirty" status.
  let editing = false;
  let originalText = $body.value;
  let originalDiskHash = $diskHash ? $diskHash.textContent.trim() : "";

  // CSRF: read from cookie. We can't getCookie cleanly without a
  // helper, so a tiny one inline:
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

  function setEditing(v) {
    editing = v;
    $body.readOnly = !v;
    $editToggle.textContent = v ? "cancel edit" : "edit";
    $validateBtn.disabled = !v;
    $saveBtn.disabled = !v;
    if (!v) {
      // Restore original on cancel.
      $body.value = originalText;
      setStatus("", "");
    } else {
      $body.focus();
    }
  }

  $editToggle.addEventListener("click", () => setEditing(!editing));

  async function postJSON(url, body) {
    const r = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": getCookie("notrouter_csrf"),
      },
      body: JSON.stringify(body),
    });
    let data = null;
    try { data = await r.json(); } catch (e) { /* non-JSON body */ }
    return { status: r.status, data };
  }

  $validateBtn.addEventListener("click", async () => {
    setStatus("info", "validating_");
    const { status, data } = await postJSON("/admin/api/config/validate", {
      body: $body.value,
    });
    if (status === 200 && data && data.ok) {
      setStatus("ok", "valid - safe to save");
    } else {
      const err = (data && data.error) || ("HTTP " + status);
      setStatus("error", "invalid: " + err);
    }
  });

  $saveBtn.addEventListener("click", async () => {
    setStatus("info", "saving_");
    const { status, data } = await postJSON("/admin/api/config/save", {
      body: $body.value,
      // Optimistic concurrency: server compares this against the live
      // disk hash, returns 409 on mismatch. Refresh recommended in that
      // case (somebody else saved while we were editing).
      expected_disk_hash: originalDiskHash,
    });
    if (status === 409) {
      setStatus("error", "config changed on disk while you were editing - refresh and re-edit");
      return;
    }
    if (status !== 200 || !data || !data.ok) {
      const err = (data && data.error) || ("HTTP " + status);
      setStatus("error", "save failed: " + err);
      return;
    }
    // Success. Update our notion of "what's on disk" so a subsequent
    // save in the same session works too.
    originalText = $body.value;
    originalDiskHash = data.new_hash;
    if ($diskHash) $diskHash.textContent = data.new_hash;
    setStatus("ok", "saved (backup: " + (data.backup_file || "none") + ") - reload to apply");
    setEditing(false);
    refreshDrift();
  });

  $reloadBtn.addEventListener("click", async () => {
    if (!confirm(
      "Reloading will tear down and rebuild the running pipeline.\n\n" +
      "In-flight events may be lost (~100ms outage).\n\n" +
      "Continue?"
    )) return;

    setStatus("info", "reloading_");
    const { status, data } = await postJSON("/admin/api/config/reload", {});
    if (status !== 200) {
      const err = (data && data.error) || ("HTTP " + status);
      setStatus("error", "reload failed: " + err);
      return;
    }
    if (data.ok) {
      setStatus("ok", "reloaded - now running hash " + data.applied_hash);
      if ($loadedHash) $loadedHash.textContent = data.applied_hash;
      refreshDrift();
    } else if (data.restored_from_lkg) {
      setStatus("error",
        "new config failed to start: " + (data.error || "unknown") +
        " - rolled back to last-known-good (" + data.lkg_hash + ")");
      if ($loadedHash) $loadedHash.textContent = data.lkg_hash;
      refreshDrift();
    } else {
      setStatus("error",
        "CRITICAL: " + (data.error || "pipeline is down") +
        " - container restart required");
    }
  });

  function refreshDrift() {
    if (!$driftBanner) return;
    const disk = ($diskHash && $diskHash.textContent.trim()) || "";
    const loaded = ($loadedHash && $loadedHash.textContent.trim()) || "";
    if (!disk || !loaded) return;
    if (disk === loaded) {
      $driftBanner.className = "success";
      $driftBanner.textContent = "disk file matches loaded config";
    } else {
      $driftBanner.className = "notice";
      $driftBanner.textContent =
        "disk file differs from loaded config - reload to apply";
    }
  }
})();
