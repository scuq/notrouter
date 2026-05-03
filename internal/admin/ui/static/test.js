// test.js - send a real event through the pipeline by looping back to
// the local webhook receiver.
(function () {
  const $body = document.getElementById("test-body");
  const $send = document.getElementById("test-send");
  const $clear = document.getElementById("test-clear");
  const $preset = document.getElementById("test-preset");
  const $profile = document.getElementById("test-profile");
  const $status = document.getElementById("test-status");
  const $result = document.getElementById("test-result");

  if (!$body) return;

  // Presets keyed by select value. Each is a string of JSON; we don't
  // pretty-print here because the textarea will display whatever we set.
  const PRESETS = {
    "generic": JSON.stringify({
      entity: "test-from-ui-1",
      state: "DOWN",
    }, null, 2),
    "nagios-host-down": JSON.stringify({
      host: "router-fra-01",
      type: "host",
      state: "DOWN",
      output: "PING CRITICAL - 100% packet loss",
      service: "",
    }, null, 2),
    "nagios-host-up": JSON.stringify({
      host: "router-fra-01",
      type: "host",
      state: "UP",
      output: "PING OK - Packet loss = 0%",
      service: "",
    }, null, 2),
    "nagios-svc-warn": JSON.stringify({
      host: "web-01",
      type: "service",
      service: "http",
      state: "WARNING",
      output: "HTTP WARNING: HTTP/1.1 500 Internal Server Error",
    }, null, 2),
    "nagios-svc-crit": JSON.stringify({
      host: "db-01",
      type: "service",
      service: "postgres",
      state: "CRITICAL",
      output: "CRITICAL - replica lag 600s",
    }, null, 2),
  };

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

  $preset.addEventListener("change", () => {
    const v = $preset.value;
    if (v === "custom") return;
    const text = PRESETS[v];
    if (text) $body.value = text;
    // After applying a preset, also try to pick a sensible profile.
    // Heuristic: nagios-* presets prefer the /webhook/nagios endpoint.
    if (v.startsWith("nagios-")) {
      pickProfile("nagios");
    } else {
      pickProfile("generic");
    }
  });

  function pickProfile(profileName) {
    for (const opt of $profile.options) {
      if (opt.dataset.profile === profileName) {
        opt.selected = true;
        return;
      }
    }
  }

  $clear.addEventListener("click", () => {
    $result.textContent = "no request sent yet";
    setStatus("", "");
  });

  $send.addEventListener("click", async () => {
    setStatus("info", "sending_");
    let parsed;
    try {
      parsed = JSON.parse($body.value);
    } catch (e) {
      setStatus("error", "payload is not valid JSON: " + e.message);
      return;
    }

    const path = $profile.value;
    try {
      const r = await fetch("/admin/api/test/send", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": getCookie("notrouter_csrf"),
        },
        body: JSON.stringify({
          path: path,
          payload: parsed,
        }),
      });
      const data = await r.json();
      if (r.status !== 200) {
        setStatus("error", "HTTP " + r.status + ": " + (data.error || ""));
        $result.textContent = JSON.stringify(data, null, 2);
        return;
      }
      // Success means we got A response from the webhook. The status
      // inside is the upstream's status (usually 202 Accepted).
      const upstream = data.upstream_status || 0;
      if (upstream >= 200 && upstream < 300) {
        setStatus("ok",
          "delivered to receiver (HTTP " + upstream + ") - check overview/logs for downstream effects");
      } else {
        setStatus("error", "receiver returned HTTP " + upstream);
      }
      $result.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      setStatus("error", "request failed: " + e.message);
    }
  });
})();
