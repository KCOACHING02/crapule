/*
 * Synchronisation EcoleDirecte (API non officielle, documentée par la communauté).
 * Récupère devoirs, emploi du temps, contrôles et notes de l'élève, et les range dans ses données Crapule.
 * Le mot de passe est chiffré (AES-GCM) dans la base ; il ne quitte jamais le serveur.
 */
const V = "7.12.1";
const UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 EDMOBILE v" + V;
const SCHEMA = "CREATE TABLE IF NOT EXISTS ed_links (user_id INTEGER PRIMARY KEY, ident TEXT NOT NULL, pw TEXT NOT NULL, cn TEXT, cv TEXT, eleve_id INTEGER, eleve_nom TEXT, pending TEXT, last_sync INTEGER, last_err TEXT, stats TEXT)";
let ready = false;
const schema = async env => { if (!ready) { await env.DB.prepare(SCHEMA).run(); ready = true; } };
const base = env => (env.ED_URL || "https://api.ecoledirecte.com") + "/v3";
const enc = new TextEncoder();
const b64e = s => { const u = enc.encode(s); let b = ""; for (const x of u) b += String.fromCharCode(x); return btoa(b); };
const b64d = s => { try { return new TextDecoder().decode(Uint8Array.from(atob(String(s || "")), c => c.charCodeAt(0))); } catch (e) { return ""; } };
const htmlText = h => String(h || "").replace(/<br\s*\/?>|<\/p>|<\/li>|<\/div>/gi, "\n").replace(/<li[^>]*>/gi, "• ").replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
const dk = t => new Date(t).toISOString().slice(0, 10);

/* ---- chiffrement du mot de passe ---- */
async function key(env) {
  const raw = await crypto.subtle.digest("SHA-256", enc.encode("crapule-ed:" + (env.ED_SECRET || env.INSTALL_TOKEN || "crapule")));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function seal(env, s) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(env), enc.encode(s))); const all = new Uint8Array(12 + ct.length); all.set(iv); all.set(ct, 12); let b = ""; for (const x of all) b += String.fromCharCode(x); return btoa(b); }
async function unseal(env, s) { const all = Uint8Array.from(atob(s), c => c.charCodeAt(0)); return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: all.slice(0, 12) }, await key(env), all.slice(12))); }

/* ---- session HTTP ---- */
class Sess {
  constructor(env, st) { this.env = env; this.cookies = (st && st.cookies) || {}; this.gtk = st && st.gtk || ""; this.token = st && st.token || ""; }
  dump() { return { cookies: this.cookies, gtk: this.gtk, token: this.token }; }
  eat(r) {
    const list = typeof r.headers.getSetCookie === "function" ? r.headers.getSetCookie() : (r.headers.get("set-cookie") || "").split(/,(?=\s*[^;=]+=)/);
    for (const c of list) { const m = String(c).match(/^\s*([^=;\s]+)=([^;]*)/); if (m) this.cookies[m[1]] = m[2]; }
    const t = r.headers.get("x-token"); if (t) this.token = t;
  }
  cookieHeader() { return Object.entries(this.cookies).map(([k, v]) => k + "=" + v).join("; "); }
  async initGtk() {
    const r = await fetch(base(this.env) + "/login.awp?gtk=1&v=" + V, { headers: { "User-Agent": UA } });
    this.eat(r); this.gtk = this.cookies.GTK || ""; await r.text().catch(() => "");
  }
  async post(path, data, login = false) {
    const h = { "User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json, text/plain, */*" };
    if (this.token) h["X-Token"] = this.token;
    if (login && this.gtk) h["X-Gtk"] = this.gtk;
    const ck = this.cookieHeader(); if (ck) h.Cookie = ck;
    const r = await fetch(base(this.env) + path + (path.includes("?") ? "&" : "?") + "v=" + V, { method: "POST", headers: h, body: "data=" + encodeURIComponent(JSON.stringify(data || {})) });
    this.eat(r);
    let j; try { j = await r.json(); } catch (e) { throw new Error("Réponse EcoleDirecte illisible (" + r.status + ")"); }
    if (j && j.token) this.token = j.token;
    return j || {};
  }
  login(ident, pw, cn, cv) {
    const d = { identifiant: ident, motdepasse: pw, isRelogin: false, uuid: "" };
    if (cn && cv) d.fa = [{ cn, cv, uniq: false }];
    return this.post("/login.awp", d, true);
  }
}

function pickEleve(accounts, nomHint) {
  const a = (accounts || [])[0]; if (!a) return null;
  if (a.typeCompte === "E") return { id: a.id, nom: a.prenom || a.identifiant };
  const els = (a.profile && a.profile.eleves) || [];
  const hint = String(nomHint || "").toLowerCase();
  const e = els.find(x => hint && String(x.prenom || "").toLowerCase() === hint) || els[0];
  return e ? { id: e.id, nom: e.prenom || "" } : null;
}
async function question(sess) {
  const q = await sess.post("/connexion/doubleauth.awp?verbe=get", {});
  const d = q.data || {};
  return { question: b64d(d.question), choix: (d.propositions || []).map(b64d) };
}

/* ---- synchronisation ---- */
async function getDoc(env, uid, id) { const r = await env.DB.prepare("SELECT data FROM docs WHERE user_id = ? AND id = ?").bind(uid, id).first(); return r ? JSON.parse(r.data) : null; }
async function putDoc(env, uid, id, data) { await env.DB.prepare("INSERT INTO docs (user_id, id, data, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT (user_id, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at").bind(uid, id, JSON.stringify(data), new Date().toISOString()).run(); }

async function syncNow(env, sess, uid, eid) {
  const now = Date.now(), today = dk(now), stats = { devoirs: 0, notes: 0, cours: 0 };
  // Devoirs
  const cdt = await sess.post(`/Eleves/${eid}/cahierdetexte.awp?verbe=get`, {});
  const days = Object.keys(cdt.data || {}).filter(d => d >= today && d <= dk(now + 21 * 864e5)).sort().slice(0, 12);
  const controles = [];
  for (const d of days) {
    let det = {}; try { det = await sess.post(`/Eleves/${eid}/cahierdetexte/${d}.awp?verbe=get`, {}); } catch (e) {}
    const byId = {}; for (const m of (det.data && det.data.matieres) || []) if (m.aFaire) byId[m.aFaire.idDevoir || m.id] = m;
    for (const it of cdt.data[d] || []) {
      const m = byId[it.idDevoir] || {}, txt = htmlText(b64d(m.aFaire && m.aFaire.contenu));
      let first = (txt.split("\n").find(x => x.trim().length > 2) || "").replace(/^[•\-*\s]+/, "").slice(0, 90);
      if (it.interrogation) first = first.replace(/^(contr[ôo]le|interro(gation)?|ds|devoir surveill[ée])\s*(:|-|sur)?\s*/i, "");
      if (first) first = first.charAt(0).toUpperCase() + first.slice(1);
      const id = "d_ed" + it.idDevoir, old = await getDoc(env, uid, id);
      const titre = (it.interrogation ? "📝 Contrôle : " : "") + (first || "Travail de " + String(it.matiere || "").toLowerCase());
      const doc = old ? { ...old, titre: old.titreEdite ? old.titre : titre, consigne: txt.slice(0, 4000) || old.consigne, pour: d, matiere: old.matiere || it.matiere }
        : { id, matiere: it.matiere || "Autre", titre, consigne: txt.slice(0, 4000), pour: d, statut: it.effectue ? "rendu" : "a_faire", createdAt: Date.parse(it.donneLe || today) || now, source: "ed", interro: !!it.interrogation, prof: m.nomProf || "" };
      if (old && old.statut === "a_faire" && it.effectue) doc.statut = "rendu";
      if (!old || JSON.stringify(old) !== JSON.stringify(doc)) await putDoc(env, uid, id, doc);
      stats.devoirs++;
      if (it.interrogation) controles.push({ date: d, matiere: it.matiere, titre: first || "Contrôle" });
    }
  }
  // Emploi du temps (2 semaines)
  let cours = [];
  try {
    const e = await sess.post(`/E/${eid}/emploidutemps.awp?verbe=get`, { dateDebut: today, dateFin: dk(now + 13 * 864e5), avecTrous: false });
    cours = (Array.isArray(e.data) ? e.data : []).filter(c => c.typeCours !== "CONGE" && c.matiere).map(c => ({ d: String(c.start_date).slice(0, 10), h: String(c.start_date).slice(11, 16), f: String(c.end_date).slice(11, 16), m: c.matiere, salle: c.salle || "", prof: c.prof || "", annule: !!c.isAnnule, modif: !!c.isModifie })).sort((a, b) => (a.d + a.h).localeCompare(b.d + b.h));
    stats.cours = cours.length;
  } catch (e) { console.log("ed edt", e && e.message); }
  await putDoc(env, uid, "ed_edt", { maj: now, cours, controles });
  // Notes
  try {
    const n = await sess.post(`/eleves/${eid}/notes.awp?verbe=get`, { anneeScolaire: "" });
    for (const x of (n.data && n.data.notes) || []) {
      const v = parseFloat(String(x.valeur).replace(",", ".")), sur = parseFloat(String(x.noteSur || "20").replace(",", ".")) || 20;
      if (x.nonSignificatif || !isFinite(v) || !x.id) continue;
      const id = "r_ed" + x.id;
      if (await getDoc(env, uid, id)) continue;
      await putDoc(env, uid, id, { id, type: "note", courseId: null, matiere: x.libelleMatiere || x.codeMatiere || "Autre", titre: x.devoir || "Note", score: Math.max(0, Math.min(1, v / sur)), note: String(x.valeur) + "/" + sur, difficulte: "moyen", rates: [], date: Date.parse((x.date || today) + "T12:00:00") || now, source: "ed" });
      stats.notes++;
    }
  } catch (e) { console.log("ed notes", e && e.message); }
  return stats;
}

async function connectAndSync(env, row) {
  const pw = await unseal(env, row.pw), sess = new Sess(env);
  await sess.initGtk();
  const r = await sess.login(row.ident, pw, row.cn, row.cv);
  if (r.code === 250) throw Object.assign(new Error("EcoleDirecte redemande la question de sécurité : reconnecte-toi dans ton profil."), { relink: true });
  if (r.code !== 200) throw new Error(r.message || "Connexion EcoleDirecte refusée (" + r.code + ")");
  const el = row.eleve_id ? { id: row.eleve_id } : pickEleve(r.data && r.data.accounts, row.eleve_nom);
  if (!el) throw new Error("Aucun élève trouvé sur ce compte EcoleDirecte.");
  return await syncNow(env, sess, row.user_id, el.id);
}

/* Synchronisation programmée de tous les comptes reliés. */
export async function syncAllEd(env) {
  await schema(env);
  const { results } = await env.DB.prepare("SELECT * FROM ed_links WHERE pending IS NULL").all();
  for (const row of results || []) {
    try { const st = await connectAndSync(env, row); await env.DB.prepare("UPDATE ed_links SET last_sync = ?, last_err = NULL, stats = ? WHERE user_id = ?").bind(Date.now(), JSON.stringify(st), row.user_id).run(); }
    catch (e) { console.log("ed sync", row.user_id, e && e.message); await env.DB.prepare("UPDATE ed_links SET last_err = ? WHERE user_id = ?").bind(String(e.message || e).slice(0, 300), row.user_id).run(); }
  }
}

export async function routeEd(env, req, url, u, fail, json) {
  if (!url.pathname.startsWith("/api/ed")) return null;
  await schema(env);
  const row = await env.DB.prepare("SELECT * FROM ed_links WHERE user_id = ?").bind(u.id).first();
  const status = r => r ? { linked: !r.pending, pending: !!r.pending, ident: r.ident, eleve: r.eleve_nom || "", lastSync: r.last_sync || null, lastErr: r.last_err || null, stats: r.stats ? JSON.parse(r.stats) : null } : { linked: false };
  if (url.pathname === "/api/ed" && req.method === "GET") return json(status(row));
  if (url.pathname === "/api/ed" && req.method === "DELETE") { await env.DB.prepare("DELETE FROM ed_links WHERE user_id = ?").bind(u.id).run(); return json({ ok: true }); }
  const finish = async (sess, r, ident, pwSealed, cn, cv) => {
    const el = pickEleve(r.data && r.data.accounts, u.nom);
    if (!el) fail("not_found", "Aucun élève trouvé sur ce compte EcoleDirecte.");
    await env.DB.prepare("INSERT INTO ed_links (user_id, ident, pw, cn, cv, eleve_id, eleve_nom, pending, last_sync, last_err, stats) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL) ON CONFLICT (user_id) DO UPDATE SET ident = excluded.ident, pw = excluded.pw, cn = excluded.cn, cv = excluded.cv, eleve_id = excluded.eleve_id, eleve_nom = excluded.eleve_nom, pending = NULL, last_err = NULL").bind(u.id, ident, pwSealed, cn || null, cv || null, el.id, el.nom || "").run();
    const st = await syncNow(env, sess, u.id, el.id);
    await env.DB.prepare("UPDATE ed_links SET last_sync = ?, stats = ? WHERE user_id = ?").bind(Date.now(), JSON.stringify(st), u.id).run();
    return json({ ok: true, eleve: el.nom, stats: st });
  };
  if (url.pathname === "/api/ed/link" && req.method === "POST") {
    const inp = await req.json().catch(() => ({}));
    const ident = String(inp.ident || "").trim(), pw = String(inp.pw || "");
    if (!ident || !pw) fail("invalid_argument", "Identifiant et mot de passe requis.");
    const sess = new Sess(env); await sess.initGtk();
    const r = await sess.login(ident, pw);
    const sealed = await seal(env, pw);
    if (r.code === 200) return await finish(sess, r, ident, sealed);
    if (r.code === 250) {
      const q = await question(sess);
      await env.DB.prepare("INSERT INTO ed_links (user_id, ident, pw, pending) VALUES (?, ?, ?, ?) ON CONFLICT (user_id) DO UPDATE SET ident = excluded.ident, pw = excluded.pw, pending = excluded.pending").bind(u.id, ident, sealed, JSON.stringify(sess.dump())).run();
      return json({ ok: false, question: q.question, choix: q.choix });
    }
    fail("bad_credentials", r.code === 505 ? "Identifiant ou mot de passe EcoleDirecte incorrect." : (r.message || "EcoleDirecte refuse la connexion (" + r.code + ")."));
  }
  if (url.pathname === "/api/ed/answer" && req.method === "POST") {
    if (!row || !row.pending) fail("invalid_argument", "Recommence la connexion.");
    const inp = await req.json().catch(() => ({}));
    const sess = new Sess(env, JSON.parse(row.pending));
    const a = await sess.post("/connexion/doubleauth.awp?verbe=post", { choix: b64e(String(inp.choix || "")) });
    const cn = a.data && a.data.cn, cv = a.data && a.data.cv;
    if (a.code !== 200 || !cn || !cv) { await env.DB.prepare("DELETE FROM ed_links WHERE user_id = ?").bind(u.id).run(); fail("bad_answer", "Mauvaise réponse à la question de sécurité. Recommence."); }
    const pw = await unseal(env, row.pw);
    sess.token = ""; await sess.initGtk();
    const r = await sess.login(row.ident, pw, cn, cv);
    if (r.code !== 200) fail("bad_credentials", r.message || "Connexion refusée après la question de sécurité.");
    return await finish(sess, r, row.ident, row.pw, cn, cv);
  }
  if (url.pathname === "/api/ed/sync" && req.method === "POST") {
    if (!row || row.pending) fail("invalid_argument", "EcoleDirecte n'est pas connecté.");
    if (row.last_sync && Date.now() - row.last_sync < 2 * 60000) return json({ ok: true, stats: row.stats ? JSON.parse(row.stats) : null, recent: true });
    try { const st = await connectAndSync(env, row); await env.DB.prepare("UPDATE ed_links SET last_sync = ?, last_err = NULL, stats = ? WHERE user_id = ?").bind(Date.now(), JSON.stringify(st), u.id).run(); return json({ ok: true, stats: st }); }
    catch (e) { await env.DB.prepare("UPDATE ed_links SET last_err = ? WHERE user_id = ?").bind(String(e.message).slice(0, 300), u.id).run(); fail(e.relink ? "relink" : "ed_error", e.message, 502); }
  }
  return null;
}
