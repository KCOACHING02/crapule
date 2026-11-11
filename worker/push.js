/* Crapule — rappels sur le téléphone (Web Push, RFC 8030/8291/8292), sans service tiers.
   Les clés VAPID sont créées au premier usage et gardées dans la base (table meta). */

const enc = new TextEncoder();
const b64u = (buf) => { const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf); let s = ""; for (const x of u) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64u = (s) => { s = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const cat = (...a) => { const n = a.reduce((x, y) => x + y.length, 0), o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
async function hmac(key, data) { const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return new Uint8Array(await crypto.subtle.sign("HMAC", k, data)); }

let ready = false;
export async function pushSchema(env) {
  if (ready) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, user_id INTEGER NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL, ua TEXT, created_at TEXT NOT NULL, last_ok TEXT, fails INTEGER NOT NULL DEFAULT 0)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS push_sent (user_id INTEGER NOT NULL, k TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY (user_id, k))").run();
  ready = true;
}
async function vapid(env) {
  const r = await env.DB.prepare("SELECT v FROM meta WHERE k = 'vapid'").first();
  if (r) { const j = JSON.parse(r.v); return { pub: j.pub, key: await crypto.subtle.importKey("jwk", j.priv, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]) }; }
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = b64u(await crypto.subtle.exportKey("raw", kp.publicKey)), priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  await env.DB.prepare("INSERT OR IGNORE INTO meta (k, v) VALUES ('vapid', ?)").bind(JSON.stringify({ pub, priv })).run();
  return vapid(env); // relit la valeur gardée (si deux appels simultanés)
}
export async function vapidPublic(env) { await pushSchema(env); return (await vapid(env)).pub; }

async function encrypt(sub, payload) {
  const ua = unb64u(sub.p256dh), auth = unb64u(sub.auth);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const prkKey = await hmac(auth, shared);
  const ikm = (await hmac(prkKey, cat(enc.encode("WebPush: info\0"), ua, asPub, new Uint8Array([1])))).slice(0, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16)), prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, cat(enc.encode("Content-Encoding: aes128gcm\0"), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, cat(enc.encode("Content-Encoding: nonce\0"), new Uint8Array([1])))).slice(0, 12);
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, cat(enc.encode(payload), new Uint8Array([2]))));
  const head = new Uint8Array(21); head.set(salt, 0); new DataView(head.buffer).setUint32(16, 4096); head[20] = 65;
  return cat(head, asPub, ct);
}
async function jwt(env, aud) {
  const v = await vapid(env), h = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const c = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "mailto:crapule@norvy.app" })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, v.key, enc.encode(h + "." + c));
  return { t: `${h}.${c}.${b64u(sig)}`, k: v.pub };
}
/* Envoie une notification à un appareil. Renvoie true si acceptée ; supprime l'abonnement s'il n'existe plus. */
export async function pushOne(env, sub, msg) {
  const body = await encrypt(sub, JSON.stringify(msg)), u = new URL(sub.endpoint), v = await jwt(env, u.origin);
  let r; try { r = await fetch(sub.endpoint, { method: "POST", headers: { TTL: "86400", Urgency: msg.urgent ? "high" : "normal", "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", Authorization: `vapid t=${v.t}, k=${v.k}`, Topic: String(msg.tag || "crapule").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 32) }, body }); }
  catch (e) { await env.DB.prepare("UPDATE push_subs SET fails = fails + 1 WHERE endpoint = ?").bind(sub.endpoint).run(); return false; }
  if (r.status === 404 || r.status === 410) { await env.DB.prepare("DELETE FROM push_subs WHERE endpoint = ?").bind(sub.endpoint).run(); return false; }
  if (!r.ok) { await env.DB.prepare("UPDATE push_subs SET fails = fails + 1 WHERE endpoint = ?").bind(sub.endpoint).run(); return false; }
  await env.DB.prepare("UPDATE push_subs SET last_ok = ?, fails = 0 WHERE endpoint = ?").bind(new Date().toISOString(), sub.endpoint).run();
  return true;
}
export async function pushUser(env, userId, msg) {
  await pushSchema(env);
  const { results } = await env.DB.prepare("SELECT * FROM push_subs WHERE user_id = ?").bind(userId).all();
  let n = 0; for (const s of results || []) if (await pushOne(env, s, msg)) n++;
  return n;
}
export async function saveSub(env, userId, sub, ua) {
  await pushSchema(env);
  const ep = String(sub?.endpoint || ""), p = String(sub?.keys?.p256dh || ""), a = String(sub?.keys?.auth || "");
  if (!/^https:\/\//.test(ep) || !p || !a) throw new Error("Abonnement invalide");
  await env.DB.prepare("INSERT OR REPLACE INTO push_subs (endpoint, user_id, p256dh, auth, ua, created_at, fails) VALUES (?, ?, ?, ?, ?, ?, 0)").bind(ep, userId, p, a, String(ua || "").slice(0, 160), new Date().toISOString()).run();
}
export async function dropSub(env, userId, endpoint) { await pushSchema(env); await env.DB.prepare("DELETE FROM push_subs WHERE user_id = ? AND endpoint = ?").bind(userId, String(endpoint || "")).run(); }
export async function subsCount(env, userId) { await pushSchema(env); return (await env.DB.prepare("SELECT COUNT(*) AS n FROM push_subs WHERE user_id = ?").bind(userId).first())?.n || 0; }


/* ---------- rappels de révision ---------- */
const TZ = "Africa/Casablanca";
const localDate = (t = Date.now()) => new Intl.DateTimeFormat("fr-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(t));
export const localHour = () => parseInt(new Intl.DateTimeFormat("fr-FR", { timeZone: TZ, hour: "2-digit", hour12: false }).format(new Date()), 10) % 24;

function streakOf(dates, today) {
  const set = new Set(dates); let n = 0, t = Date.parse(today + "T12:00:00Z");
  if (!set.has(today)) t -= 864e5;
  while (set.has(new Date(t).toISOString().slice(0, 10))) { n++; t -= 864e5; }
  return n;
}
/* Appelé chaque heure : rappel de révision, devoirs du lendemain, série en danger. */
export async function runReminders(env) {
  await pushSchema(env);
  const hour = localHour(), today = localDate(), tomorrow = localDate(Date.now() + 864e5);
  if (hour < 7 || hour > 21) return 0;
  const { results: us } = await env.DB.prepare("SELECT DISTINCT u.id, u.nom FROM users u JOIN push_subs s ON s.user_id = u.id WHERE u.role = 'eleve'").all();
  let sent = 0;
  for (const u of us || []) {
    const { results: docs } = await env.DB.prepare("SELECT id, data FROM docs WHERE user_id = ? AND (id = 'profile' OR id LIKE 'r\\_%' ESCAPE '\\' OR id LIKE 'd\\_%' ESCAPE '\\')").bind(u.id).all();
    let prof = {}; const dates = [], dues = [];
    for (const r of docs || []) {
      let v; try { v = JSON.parse(r.data); } catch (e) { continue; }
      if (r.id === "profile") prof = v;
      else if (r.id.startsWith("r_") && v.date) dates.push(localDate(v.date));
      else if (r.id.startsWith("d_") && v.statut === "a_faire" && v.pour === tomorrow) dues.push(v);
    }
    if (prof.rappels === false) continue;
    const H = Number.isInteger(+prof.rappelHeure) ? +prof.rappelHeure : 18;
    const active = dates.includes(today), streak = streakOf(dates, today);
    const msgs = [];
    if (hour === H && !active) msgs.push({ k: "rev:" + today, title: "🦊 Ta révision du jour t'attend", body: streak > 0 ? `Garde ta série de ${streak} jour${streak > 1 ? "s" : ""} 🔥 — 15 minutes suffisent.` : "15 minutes pour progresser, on y va ?", url: "./#planning", tag: "revision" });
    if (hour === H) for (const d of dues) msgs.push({ k: "dev:" + d.id + ":" + today, title: "📚 Devoir pour demain", body: `${d.titre} (${d.matiere})`, url: "./#devoirs", tag: "devoir-" + String(d.id).slice(-8) });
    if (hour === Math.min(21, H + 3) && hour !== H && !active && streak >= 2) msgs.push({ k: "serie:" + today, title: `🔥 Ta série de ${streak} jours est en danger !`, body: "Un petit quiz de 5 minutes et elle est sauvée.", url: "./", tag: "serie" });
    if (!msgs.length) continue;
    const { results: done } = await env.DB.prepare("SELECT k FROM push_sent WHERE user_id = ?").bind(u.id).all();
    const seen = new Set((done || []).map(r => r.k));
    for (const m of msgs) {
      if (seen.has(m.k)) continue;
      if (await pushUser(env, u.id, m)) sent++;
      await env.DB.prepare("INSERT OR REPLACE INTO push_sent (user_id, k, at) VALUES (?, ?, ?)").bind(u.id, m.k, new Date().toISOString()).run();
    }
  }
  await env.DB.prepare("DELETE FROM push_sent WHERE at < ?").bind(new Date(Date.now() - 60 * 864e5).toISOString()).run();
  return sent;
}
