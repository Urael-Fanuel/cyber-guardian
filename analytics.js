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

  function currentLang() {
    try {
      return localStorage.getItem("cg-lang") || document.documentElement.lang || (navigator.language || "en").slice(0, 2);
    } catch {
      return document.documentElement.lang || "en";
    }
  }

  function deviceType() {
    const width = window.innerWidth || 0;
    if (width && width < 640) return "mobile";
    if (width && width < 1024) return "tablet";
    return "desktop";
  }

  function baseMetadata() {
    return {
      lang: currentLang(),
      dir: document.documentElement.dir || "ltr",
      device: deviceType(),
      viewport: `${window.innerWidth || 0}x${window.innerHeight || 0}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    };
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
      metadata: cleanMetadata({ ...baseMetadata(), ...(metadata || {}) }),
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
    const typeMatch = href.match(/[?&]type=([^&#]+)/i);
    const contactType = typeMatch ? decodeURIComponent(typeMatch[1]).toLowerCase() : "";
    if (contactType === "sales" || text.includes("sales")) {
      track("contact_sales_clicked", { href, label: text.slice(0, 80), type: "sales" });
    } else if (contactType === "enterprise") {
      track("contact_enterprise_clicked", { href, label: text.slice(0, 80), type: "enterprise" });
    } else if (contactType === "support") {
      track("contact_support_clicked", { href, label: text.slice(0, 80), type: "support" });
    } else if (contactType === "security") {
      track("contact_security_clicked", { href, label: text.slice(0, 80), type: "security" });
    } else if (href.includes("contact.html")) {
      track("contact_clicked", { href, label: text.slice(0, 80), type: contactType || "general" });
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => track("page_view", { title: document.title }));
  } else {
    track("page_view", { title: document.title });
  }
})();
