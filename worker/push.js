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
/* Appelé chaque heure : de l'heure de rappel (18 h par défaut) jusqu'à 21 h, un rappel par heure tant que la révision du jour n'est pas faite, et un rappel par heure tant qu'il reste des devoirs pour demain. */
export async function runReminders(env) {
  await pushSchema(env);
  const hour = localHour(), today = localDate(), tomorrow = localDate(Date.now() + 864e5);
  if (hour < 7 || hour > 21) return 0;
  const { results: us } = await env.DB.prepare("SELECT DISTINCT u.id, u.nom FROM users u JOIN push_subs s ON s.user_id = u.id WHERE u.role = 'eleve'").all();
  let sent = 0;
  for (const u of us || []) {
    const { results: docs } = await env.DB.prepare("SELECT id, data FROM docs WHERE user_id = ? AND (id = 'profile' OR id LIKE 'r\\_%' ESCAPE '\\' OR id LIKE 'd\\_%' ESCAPE '\\')").bind(u.id).all();
    let prof = {}; const dates = [], dues = [], res = [];
    for (const r of docs || []) {
      let v; try { v = JSON.parse(r.data); } catch (e) { continue; }
      if (r.id === "profile") prof = v;
      else if (r.id.startsWith("r_") && v.date) { if (v.type !== "note") dates.push(localDate(v.date)); res.push(v); }
      else if (r.id.startsWith("d_") && v.statut === "a_faire" && v.pour === tomorrow) dues.push(v);
    }
    if (prof.rappels === false) continue;
    const H = Number.isInteger(+prof.rappelHeure) ? +prof.rappelHeure : 18;
    const active = dates.includes(today), streak = streakOf(dates, today);
    const msgs = [];
    const weak = weakSpot(res), idle = idleDays(dates, today);
    const coachUrl = weak ? "./#coach=" + encodeURIComponent(JSON.stringify([weak.mat, weak.label])) : "./";
    const last = 21, inWindow = hour >= H && hour <= last, step = hour - H;
    if (inWindow && !active) {
      const k = "rev:" + today + ":" + hour, tag = "revision", w = weak ? `« ${weak.label.slice(0, 50)} »` : "";
      if (step === 0) {
        if (idle >= 2) msgs.push({ k, title: "🦊 On reprend doucement ?", body: weak ? `Juste 5 minutes sur ${w} et c'est reparti. Tu vas y arriver 💪` : "Juste 5 minutes aujourd'hui, et c'est reparti 💪", url: coachUrl, tag });
        else if (weak) msgs.push({ k, title: "🎯 Coup de pouce de 5 minutes", body: `${w} (${weak.mat}) te joue des tours. On le règle ensemble${streak > 0 ? `, et ta série de ${streak} 🔥 reste en vie` : ""} ?`, url: coachUrl, tag });
        else msgs.push({ k, title: "🦊 Ta révision du jour t'attend", body: streak > 0 ? `Garde ta série de ${streak} jour${streak > 1 ? "s" : ""} 🔥 — 15 minutes suffisent.` : "15 minutes pour progresser, on y va ?", url: "./#planning", tag });
      } else { const t = pickOf(TAQ_REV[hour === last ? "last" : step === 1 ? "h1" : "h2"], today + hour); msgs.push({ k, title: t[0], body: t[1] + (streak >= 2 ? ` Ta série de ${streak} jours 🔥 compte sur toi.` : ""), url: coachUrl, tag }); }
    }
    const cheer = active && hour === Math.min(last, H + 2) ? cheerOf(res, today, streak) : null;
    if (cheer) msgs.push({ k: "bravo:" + today, ...cheer, url: "./", tag: "bravo" });
    if (inWindow && dues.length) {
      const one = dues.length === 1, d = dues[0];
      msgs.push({ k: "dev:" + today + ":" + hour, tag: "devoirs", url: "./#devoirs",
        title: step === 0 ? (one ? "📚 Devoir pour demain" : `📚 ${dues.length} devoirs pour demain`) : pickOf(TAQ_DEV[hour === last ? "last" : step === 1 ? "h1" : "h2"], today + hour + "d"),
        body: (one ? `${d.titre} (${d.matiere})` : dues.slice(0, 3).map(x => `${x.matiere} : ${String(x.titre).slice(0, 40)}`).join(" · ")) + (step === 0 ? "" : " — coche-l${one ? "e" : "es"} dans l'app quand c'est fait ✅") });
    }
    if (!msgs.length) continue;
    const { results: done } = await env.DB.prepare("SELECT k FROM push_sent WHERE user_id = ?").bind(u.id).all();
    const seen = new Set((done || []).map(r => r.k));
    for (const m of msgs) {
      if (seen.has(m.k)) continue;
      if (await pushUser(env, u.id, m)) sent++;
      await env.DB.prepare("INSERT OR REPLACE INTO push_sent (user_id, k, at) VALUES (?, ?, ?)").bind(u.id, m.k, new Date().toISOString()).run();
    }
  }
  sent += await weeklyParentReport(env, hour, today);
  sent += await parentAlerts(env, hour, today);
  await env.DB.prepare("DELETE FROM push_sent WHERE at < ?").bind(new Date(Date.now() - 60 * 864e5).toISOString()).run();
  return sent;
}

/* Rappels taquins (même ton qu'un grand frère) : choisis au hasard mais stables pour une heure donnée. */
const pickOf = (list, seed) => { let h = 0; for (const c of String(seed)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return list[h % list.length]; };
const TAQ_REV = {
  h1: [["😏 Toujours rien ?", "Crapule commence à s'impatienter… 5 minutes, c'est tout ce que je demande."], ["👀 Je te vois…", "Tu scrolles au lieu de réviser ? 5 minutes et je te laisse tranquille."], ["⏰ Hé ho, t'es où ?", "Ta révision du jour t'attend toujours. Allez, 5 minutes chrono !"]],
  h2: [["🥊 Tu cherches la bagarre ?", "Toujours pas fait tes exercices ? Viens, on règle ça en 5 minutes."], ["😤 Bon, ça suffit maintenant !", "Le renard ne lâchera pas l'affaire. 5 minutes et on n'en parle plus."], ["🦊 Crapule n'est pas content…", "Toujours rien aujourd'hui ? Même un mini-quiz, ça compte !"], ["🙄 T'attends quoi pour tes exercices, p'tit con ?", "5 minutes, pas une de plus. Allez, hop !"]],
  last: [["🌙 Dernier avertissement !", "Après, je vais me coucher vexé. 5 minutes avant de dormir ?"], ["🛌 Avant de dormir…", "Un petit quiz de 5 minutes et je te fiche la paix jusqu'à demain 😇"], ["🚨 Dernière chance !", "Le renard ne dormira pas tant que ce n'est pas fait. 5 minutes !"]]
};
const TAQ_DEV = {
  h1: ["😏 Toujours pas fait tes devoirs ?", "👀 Les devoirs ne vont pas se faire tout seuls…", "📚 Hé ho, tes devoirs pour demain !"],
  h2: ["🥊 Toujours pas fait tes devoirs ? Tu cherches la bagarre ?", "😤 Tes devoirs pour demain, c'est maintenant !", "🦊 Crapule surveille tes devoirs…", "🙄 T'attends quoi pour tes devoirs, p'tit con ?"],
  last: ["🌙 Dernier rappel : tes devoirs pour demain !", "🚨 Dernière chance pour tes devoirs !", "🛌 Pas de dodo avant les devoirs !"]
};
/* Point faible principal : notions ratées récemment (quiz, exercices, copies analysées) et mauvaises notes. */
function weakSpot(res) {
  const lim = Date.now() - 30 * 864e5, cnt = {};
  for (const r of res) {
    if (!(r.date > lim)) continue;
    if (r.type === "quiz" || r.type === "exo" || (r.type === "note" && r.analyse)) for (const x of r.rates || []) if (x) { const k = (r.matiere || "Autre") + "\u0000" + x; cnt[k] = (cnt[k] || 0) + 1; }
  }
  // une notion réussie dans un quiz ciblé récent n'est plus un point faible
  for (const r of res) if (r.type === "quiz" && r.focus && r.score >= 0.8 && r.date > Date.now() - 7 * 864e5) delete cnt[(r.matiere || "Autre") + "\u0000" + r.focus];
  const best = Object.entries(cnt).sort((a, b) => b[1] - a[1])[0];
  if (best && best[1] >= 2) { const [mat, label] = best[0].split("\u0000"); return { mat, label, n: best[1] }; }
  const low = res.filter(r => r.type === "note" && r.score < 0.5 && r.date > Date.now() - 45 * 864e5).sort((a, b) => b.date - a.date)[0];
  return low ? { mat: low.matiere || "Autre", label: String(low.titre || "ton dernier devoir").slice(0, 60), n: 1 } : null;
}
function idleDays(dates, today) {
  if (!dates.length) return 0;
  const last = dates.sort().at(-1); return Math.round((Date.parse(today) - Date.parse(last)) / 864e5);
}
/* Message d'encouragement du soir, seulement s'il y a une vraie raison. */
function cheerOf(res, today, streak) {
  if ([3, 5, 7, 10, 14, 21, 30, 50, 100].includes(streak)) return { title: `🔥 ${streak} jours de suite !`, body: streak >= 7 ? "Franchement, chapeau. Tu es en train de prendre une vraie habitude 👏" : "Tu tiens le rythme, continue comme ça 💪" };
  const t = res.filter(r => r.type !== "note" && r.date && localDate(r.date) === today && typeof r.score === "number");
  const fixed = t.find(r => r.focus && r.score >= 0.8);
  if (fixed) return { title: "💪 Point faible en train de tomber !", body: `${Math.round(fixed.score * 100)} % sur « ${String(fixed.focus).slice(0, 50)} ». Tu vois que tu peux le faire 🦊` };
  const top = t.sort((a, b) => b.score - a.score)[0];
  if (top && top.score >= 0.85) return { title: `🎉 ${Math.round(top.score * 100)} % en ${String(top.matiere || "révision").slice(0, 30)} !`, body: "Super séance aujourd'hui. Fier de toi 👏" };
  return null;
}

/* Bilan de la semaine envoyé au parent le dimanche à 18 h. */
async function weeklyParentReport(env, hour, today) {
  const dow = new Date(today + "T12:00:00Z").getUTCDay();
  if (dow !== 0 || hour !== 18) return 0;
  const { results: parents } = await env.DB.prepare("SELECT DISTINCT u.id FROM users u JOIN push_subs s ON s.user_id = u.id WHERE u.role = 'parent'").all();
  if (!parents || !parents.length) return 0;
  const { results: kids } = await env.DB.prepare("SELECT u.id, u.nom, d.data FROM users u LEFT JOIN docs d ON d.user_id = u.id AND d.id = 'suivi' WHERE u.role = 'eleve'").all();
  const lines = [];
  for (const k of kids || []) {
    let v = {}; try { v = JSON.parse(k.data || "{}"); } catch (e) {}
    const nom = v.prenom || k.nom || "Élève";
    const wk = Date.now() - 7 * 864e5;
    const moves = (v.matieres || []).map(m => { const s = m.serie || []; const b = [...s].reverse().find(p => p.d < wk); return b && s.length ? { n: m.n, d: s[s.length - 1].l - b.l } : null; }).filter(x => x && x.d);
    const best = moves.sort((a, b) => b.d - a.d)[0];
    let t = `${nom} : ${v.jours7 ?? 0} j actifs, ${v.semaine || 0} entraînements`;
    if (best && best.d > 0) t += `, ${best.n} +${best.d}`;
    if (v.devoirs && v.devoirs.retard) t += `, ⚠️ ${v.devoirs.retard} devoir(s) en retard`;
    lines.push(t);
  }
  if (!lines.length) return 0;
  let sent = 0;
  for (const p of parents) {
    const key = "bilan:" + today;
    const seen = await env.DB.prepare("SELECT 1 FROM push_sent WHERE user_id = ? AND k = ?").bind(p.id, key).first();
    if (seen) continue;
    if (await pushUser(env, p.id, { title: "📊 Le bilan de la semaine", body: lines.join(" · "), url: "./#suivi", tag: "bilan" })) sent++;
    await env.DB.prepare("INSERT OR REPLACE INTO push_sent (user_id, k, at) VALUES (?, ?, ?)").bind(p.id, key, new Date().toISOString()).run();
  }
  return sent;
}

/* Alertes au parent (19 h) : 3 jours sans révision, ou matière en forte baisse sur 7 jours. */
async function parentAlerts(env, hour, today) {
  if (hour !== 19) return 0;
  const { results: parents } = await env.DB.prepare("SELECT DISTINCT u.id FROM users u JOIN push_subs s ON s.user_id = u.id WHERE u.role = 'parent'").all();
  if (!parents || !parents.length) return 0;
  const { results: kids } = await env.DB.prepare("SELECT u.id, u.nom, d.data FROM users u LEFT JOIN docs d ON d.user_id = u.id AND d.id = 'suivi' WHERE u.role = 'eleve'").all();
  const alerts = [];
  for (const k of kids || []) {
    const { results: rs } = await env.DB.prepare("SELECT data FROM docs WHERE user_id = ? AND id LIKE 'r\\_%' ESCAPE '\\'").bind(k.id).all();
    let last = 0; for (const r of rs || []) { try { last = Math.max(last, JSON.parse(r.data).date || 0); } catch (e) {} }
    let v = {}; try { v = JSON.parse(k.data || "{}"); } catch (e) {}
    const nom = v.prenom || k.nom || "Ton enfant";
    if (last) {
      const lastDay = localDate(last), idle = Math.round((Date.parse(today) - Date.parse(lastDay)) / 864e5);
      if (idle >= 3) alerts.push({ k: "decro:" + k.id + ":" + lastDay, title: `😴 ${nom} n'a pas révisé depuis ${idle} jours`, body: "Un petit mot d'encouragement peut l'aider à reprendre.", url: "./#suivi", tag: "decro-" + k.id });
    }
    const wk = Date.now() - 7 * 864e5;
    for (const m of v.matieres || []) {
      const s = m.serie || []; const b = [...s].reverse().find(p => p.d < wk);
      if (b && s.length && s[s.length - 1].l - b.l <= -15) alerts.push({ k: "baisse:" + k.id + ":" + m.n + ":" + today.slice(0, 8), title: `📉 ${nom} : ${m.n} en baisse`, body: `Niveau passé de ${b.l} à ${s[s.length - 1].l}/100 cette semaine.`, url: "./#suivi", tag: "baisse-" + k.id });
    }
  }
  let sent = 0;
  for (const p of parents) for (const a of alerts) {
    const seen = await env.DB.prepare("SELECT 1 FROM push_sent WHERE user_id = ? AND k = ?").bind(p.id, a.k).first();
    if (seen) continue;
    if (await pushUser(env, p.id, a)) sent++;
    await env.DB.prepare("INSERT OR REPLACE INTO push_sent (user_id, k, at) VALUES (?, ?, ?)").bind(p.id, a.k, new Date().toISOString()).run();
  }
  return sent;
}
