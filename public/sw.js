/* Crapule — notifications + mode hors connexion.
   Toujours le réseau d'abord (l'appli reste à jour) ; la copie en cache ne sert que sans connexion. */
const SHELL = "crapule-app-v3", DATA = "crapule-data";
self.addEventListener("install", e => { e.waitUntil(caches.open(SHELL).then(c => c.addAll(["/", "/manifest.webmanifest", "/icons/icon-192.png"])).catch(() => {})); self.skipWaiting(); });
self.addEventListener("activate", e => e.waitUntil((async () => { for (const k of await caches.keys()) if (k.startsWith("crapule-app-") && k !== SHELL) await caches.delete(k); await self.clients.claim(); })()));
const CACHED_API = /^\/api\/(me|docs|lib)(\/|$|\?)/;
self.addEventListener("fetch", e => {
  const req = e.request; if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin === location.origin) {
    if (url.pathname.startsWith("/api/") && !CACHED_API.test(url.pathname)) return;
    const store = url.pathname.startsWith("/api/") ? DATA : SHELL;
    e.respondWith(fetch(req).then(r => { if (r.ok) { const cp = r.clone(); caches.open(store).then(c => c.put(req.mode === "navigate" ? "/" : req, cp)); } return r; })
      .catch(async () => (await caches.match(req.mode === "navigate" ? "/" : req)) || new Response(JSON.stringify({ code: "offline", message: "Pas de connexion internet." }), { status: 503, headers: { "Content-Type": "application/json" } })));
    return;
  }
  if (/cdnjs\.cloudflare\.com|fonts\.(googleapis|gstatic)\.com|cdn\.jsdelivr\.net/.test(url.host)) {
    e.respondWith(caches.match(req).then(hit => hit || fetch(req).then(r => { const cp = r.clone(); caches.open(SHELL).then(c => c.put(req, cp)); return r; })));
  }
});
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
