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

  function getAdminToken() {
    try {
      const token = localStorage.getItem("cg-admin-token") || "";
      if (!token) return "";
      const payload = token.split(".")[0];
      if (!payload) return "";
      const parsed = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
      if (parsed.role !== "admin" || Number(parsed.exp || 0) <= Math.floor(Date.now() / 1000)) {
        localStorage.removeItem("cg-admin-token");
        return "";
      }
      return token;
    } catch {
      return "";
    }
  }

  function track(eventName, metadata) {
    const adminToken = getAdminToken();
    const payload = {
      event_name: eventName,
      page_path: location.pathname,
      referrer: document.referrer || "",
      visitor_id: visitorId(),
      scan_scope: metadata && metadata.scope,
      actor_hint: adminToken ? "owner" : "public",
      metadata: cleanMetadata(metadata),
    };

    try {
      const body = JSON.stringify(payload);
      if (!adminToken && navigator.sendBeacon) {
        const blob = new Blob([body], { type: "application/json" });
        navigator.sendBeacon(endpoint, blob);
        return;
      }
      const headers = { "Content-Type": "application/json" };
      if (adminToken) headers["X-CG-Admin-Token"] = adminToken;
      fetch(endpoint, {
        method: "POST",
        headers,
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
