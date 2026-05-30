(function () {
  const endpoint = "/api/track-event";
  const key = "cg-visitor-id";

  function visitorId() {
    try {
      let id = localStorage.getItem(key);
      if (!id) {
        id = (crypto && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now()) + "-" + Math.random().toString(16).slice(2);
        localStorage.setItem(key, id);
      }
      return id;
    } catch {
      return "";
    }
  }

  function cleanMetadata(metadata) {
    if (!metadata || typeof metadata !== "object") return {};
    const out = {};
    Object.entries(metadata).slice(0, 20).forEach(([k, v]) => {
      if (typeof v === "number" || typeof v === "boolean" || v == null) out[k] = v;
      else out[k] = String(v).slice(0, 240);
    });
    return out;
  }

  function track(eventName, metadata) {
    const payload = {
      event_name: eventName,
      page_path: location.pathname,
      referrer: document.referrer || "",
      visitor_id: visitorId(),
      scan_scope: metadata && metadata.scope,
      metadata: cleanMetadata(metadata),
    };

    try {
      const body = JSON.stringify(payload);
      if (navigator.sendBeacon) {
        const blob = new Blob([body], { type: "application/json" });
        navigator.sendBeacon(endpoint, blob);
        return;
      }
      fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        keepalive: true,
      }).catch(() => {});
    } catch {}
  }

  window.cgTrack = track;
  document.documentElement.setAttribute("data-cg-analytics", "on");

  document.addEventListener("click", event => {
    const link = event.target && event.target.closest ? event.target.closest("a,button") : null;
    if (!link) return;
    const href = link.getAttribute("href") || "";
    const text = (link.textContent || "").toLowerCase();
    if (href.includes("type=sales") || text.includes("sales")) {
      track("contact_sales_clicked", { href, label: text.slice(0, 80) });
    } else if (href.includes("contact.html")) {
      track("contact_clicked", { href, label: text.slice(0, 80) });
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => track("page_view", { title: document.title }));
  } else {
    track("page_view", { title: document.title });
  }
})();
