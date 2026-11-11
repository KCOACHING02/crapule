/* Crapule — notifications sur le téléphone (pas de cache : l'application vient toujours du serveur). */
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("push", e => {
  let m = {}; try { m = e.data ? e.data.json() : {}; } catch (_) { m = { title: "Crapule", body: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.registration.showNotification(m.title || "Crapule", { body: m.body || "", tag: m.tag || undefined, renotify: !!m.tag, icon: "icons/icon-192.png", badge: "icons/icon-192.png", data: { url: m.url || "./" } }));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = new URL(e.notification.data?.url || "./", self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(cs => {
    for (const c of cs) if (c.url.startsWith(self.registration.scope)) { c.postMessage({ type: "open", url }); return c.focus(); }
    return self.clients.openWindow(url);
  }));
});
