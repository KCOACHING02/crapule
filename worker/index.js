/*
 * Crapule — carnet de révision avec IA
 * Serveur Cloudflare Workers · Base D1 (binding DB) · Pages statiques ./public (binding ASSETS)
 * La clé Claude (secret ANTHROPIC_API_KEY) reste ici, côté serveur : le navigateur ne la voit jamais.
 */

import { vapidPublic, saveSub, dropSub, pushUser, subsCount, runReminders } from "./push.js";

const PBKDF2_ITER = 20000;
const SESSION_DAYS = 90;
const COOKIE = "crapule_sid";

class HttpError extends Error { constructor(status, code, message) { super(message); this.status = status; this.code = code; } }
const fail = (code, message, status = 400) => { throw new HttpError(status, code, message); };
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers } });
const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const enc = new TextEncoder();
const b64 = (buf) => { const u = new Uint8Array(buf); let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const randToken = () => b64(crypto.getRandomValues(new Uint8Array(24))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const safeEq = (a, b) => { if (!a || !b || a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };
const escH = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const checkId = (id) => /^[A-Za-z0-9_\-.~:@+]{1,190}$/.test(id || "") ? id : fail("invalid_argument", "Identifiant invalide");
const clientIp = (req) => req.headers.get("CF-Connecting-IP") || "local";
const day = () => new Date().toISOString().slice(0, 10);

/* ---------- base de données ---------- */
const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT NOT NULL UNIQUE, nom TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'eleve', password_hash TEXT NOT NULL, created_at TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS docs (user_id INTEGER NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (user_id, id))",
  "CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, at INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS ai_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, day TEXT NOT NULL, model TEXT NOT NULL, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, images INTEGER NOT NULL DEFAULT 0)",
  "CREATE INDEX IF NOT EXISTS ai_usage_day ON ai_usage (user_id, day)",
  "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)",
];
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  if (!env.DB) fail("no_db", "Base de données non reliée (binding DB).", 500);
  for (const s of SCHEMA) await env.DB.prepare(s).run();
  schemaReady = true;
}

/* ---------- comptes et sessions ---------- */
async function hashPassword(pw, saltB64, iter = PBKDF2_ITER) {
  const salt = saltB64 ? unb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
  return `pbkdf2$${iter}$${b64(salt)}$${b64(bits)}`;
}
async function verifyPassword(pw, stored) {
  const [alg, iter, salt, h] = String(stored).split("$");
  if (alg !== "pbkdf2") return false;
  return safeEq((await hashPassword(pw, salt, parseInt(iter, 10))).split("$")[3], h);
}
const cookieGet = (req, name) => { const m = (req.headers.get("Cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)")); return m ? m[1] : null; };
const sessionCookie = (req, tok, maxAge) => `${COOKIE}=${tok}; Path=/; HttpOnly;${new URL(req.url).protocol === "https:" ? " Secure;" : ""} SameSite=Lax; Max-Age=${maxAge}`;
async function currentUser(env, req) {
  const tok = cookieGet(req, COOKIE); if (!tok) return null;
  const row = await env.DB.prepare("SELECT u.id, u.login, u.nom, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?").bind(await sha256(tok), Date.now()).first();
  return row || null;
}
const pub = (u) => ({ id: u.id, login: u.login, nom: u.nom, role: u.role });

async function routeAuth(env, req, url) {
  if (url.pathname === "/api/login" && req.method === "POST") {
    const ip = clientIp(req);
    await env.DB.prepare("DELETE FROM login_attempts WHERE at < ?").bind(Date.now() - 86400e3).run();
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND at > ?").bind(ip, Date.now() - 900e3).first();
    if (n && n.n >= 10) fail("too_many", "Trop d'essais. Réessaie dans 15 minutes.", 429);
    const inp = await req.json().catch(() => ({}));
    const u = await env.DB.prepare("SELECT * FROM users WHERE LOWER(login) = ?").bind(String(inp.login || "").trim().toLowerCase()).first();
    if (!u || !(await verifyPassword(String(inp.password || ""), u.password_hash))) {
      await env.DB.prepare("INSERT INTO login_attempts (ip, at) VALUES (?, ?)").bind(ip, Date.now()).run();
      fail("bad_credentials", "Identifiant ou mot de passe incorrect.", 401);
    }
    const tok = randToken();
    await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(Date.now()).run();
    await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)").bind(await sha256(tok), u.id, Date.now() + SESSION_DAYS * 86400e3).run();
    return json({ user: pub(u) }, 200, { "Set-Cookie": sessionCookie(req, tok, SESSION_DAYS * 86400) });
  }
  if (url.pathname === "/api/logout" && req.method === "POST") {
    const tok = cookieGet(req, COOKIE);
    if (tok) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(tok)).run();
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(req, "", 0) });
  }
  return null;
}

/* ---------- données de l'utilisateur ---------- */
async function routeDocs(env, req, url, u) {
  if (url.pathname === "/api/docs" && req.method === "GET") {
    const { results } = await env.DB.prepare("SELECT id, data FROM docs WHERE user_id = ?").bind(u.id).all();
    return json({ items: (results || []).map(r => ({ id: r.id, data: JSON.parse(r.data) })) });
  }
  const m = url.pathname.match(/^\/api\/docs\/([^/]+)$/);
  if (m) {
    const id = checkId(decodeURIComponent(m[1]));
    if (id === "recompenses" && req.method !== "GET") fail("forbidden", "Les récompenses sont fixées par le parent.", 403);
    if (req.method === "PUT") {
      const body = await req.text();
      if (body.length > 1_800_000) fail("too_large", "Document trop volumineux.", 413);
      let data; try { data = JSON.parse(body); } catch (e) { fail("invalid_argument", "JSON invalide"); }
      if (!data || typeof data !== "object" || Array.isArray(data)) fail("invalid_argument", "Le document doit être un objet.");
      await env.DB.prepare("INSERT INTO docs (user_id, id, data, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT (user_id, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at").bind(u.id, id, body, nowIso()).run();
      return json({ ok: true });
    }
    if (req.method === "DELETE") {
      await env.DB.prepare("DELETE FROM docs WHERE user_id = ? AND id = ?").bind(u.id, id).run();
      return json({ ok: true });
    }
  }
  return null;
}

/* ---------- bibliothèque partagée (livres de référence) : user_id = 0 ---------- */
async function routeLib(env, req, url, u) {
  if (!url.pathname.startsWith("/api/lib")) return null;
  if (url.pathname === "/api/lib" && req.method === "GET") {
    const { results } = await env.DB.prepare("SELECT id, data FROM docs WHERE user_id = 0 AND id LIKE 'book\\_%' ESCAPE '\\'").all();
    return json({ items: (results || []).map(r => ({ id: r.id, data: JSON.parse(r.data) })) });
  }
  const m = url.pathname.match(/^\/api\/lib\/([^/]+)$/);
  if (!m) return null;
  const id = checkId(decodeURIComponent(m[1]));
  if (!/^(book|bkc)_/.test(id)) fail("invalid_argument", "Identifiant de livre invalide");
  if (req.method === "GET") {
    const r = await env.DB.prepare("SELECT data FROM docs WHERE user_id = 0 AND id = ?").bind(id).first();
    if (!r) fail("not_found", "Introuvable", 404);
    return new Response(r.data, { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "private, max-age=86400" } });
  }
  if (req.method === "PUT") {
    const body = await req.text();
    if (body.length > 1_800_000) fail("too_large", "Morceau trop volumineux.", 413);
    let data; try { data = JSON.parse(body); } catch (e) { fail("invalid_argument", "JSON invalide"); }
    if (!data || typeof data !== "object" || Array.isArray(data)) fail("invalid_argument", "Objet attendu");
    await env.DB.prepare("INSERT INTO docs (user_id, id, data, updated_at) VALUES (0, ?, ?, ?) ON CONFLICT (user_id, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at").bind(id, body, nowIso()).run();
    return json({ ok: true });
  }
  if (req.method === "DELETE") {
    if (!id.startsWith("book_")) fail("invalid_argument", "Supprimer un livre entier");
    const key = id.slice(5);
    await env.DB.prepare("DELETE FROM docs WHERE user_id = 0 AND (id = ? OR id LIKE ? ESCAPE '\\')").bind(id, "bkc\\_" + key.replace(/_/g, "\\_") + "\\_%").run();
    return json({ ok: true });
  }
  return null;
}

/* ---------- espace parent ---------- */
async function routeParent(env, req, url, u) {
  if (!url.pathname.startsWith("/api/suivi") && !url.pathname.startsWith("/api/usage") && !url.pathname.startsWith("/api/rewards/")) return null;
  if (u.role !== "parent") fail("forbidden", "Réservé au compte parent.", 403);
  if (url.pathname === "/api/suivi") {
    const { results } = await env.DB.prepare("SELECT u.id, u.nom, u.login, u.role, d.data, r.data AS rewards FROM users u LEFT JOIN docs d ON d.user_id = u.id AND d.id = 'suivi' LEFT JOIN docs r ON r.user_id = u.id AND r.id = 'recompenses' ORDER BY u.role DESC, u.id").all();
    return json({ items: (results || []).filter(r => r.data || r.role === "eleve").map(r => ({ id: String(r.id), data: { prenom: r.nom, ...(r.data ? JSON.parse(r.data) : {}), login: r.login, role: r.role, recompenses: r.rewards ? (JSON.parse(r.rewards).items || []) : [] } })) });
  }
  const rw = url.pathname.match(/^\/api\/rewards\/(\d+)$/);
  if (rw && req.method === "PUT") {
    const target = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(+rw[1]).first();
    if (!target || target.role !== "eleve") fail("not_found", "Élève introuvable.", 404);
    const inp = await req.json().catch(() => ({}));
    const items = (Array.isArray(inp.items) ? inp.items : []).slice(0, 30).map(x => ({ id: String(x.id || "").slice(0, 40), titre: String(x.titre || "").slice(0, 120), type: ["serie", "niveau", "quiz", "points"].includes(x.type) ? x.type : "serie", objectif: Math.max(1, Math.min(100000, parseInt(x.objectif, 10) || 1)), donnee: !!x.donnee, creeLe: x.creeLe || nowIso() })).filter(x => x.titre && x.id);
    await env.DB.prepare("INSERT INTO docs (user_id, id, data, updated_at) VALUES (?, 'recompenses', ?, ?) ON CONFLICT (user_id, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at").bind(target.id, JSON.stringify({ items }), nowIso()).run();
    if (inp.notify && items.length) { try { await pushUser(env, target.id, { title: "🎁 Nouvelle récompense à gagner !", body: items[items.length - 1].titre, url: "./#trophees", tag: "recompense" }); } catch (e) {} }
    return json({ ok: true, items });
  }
  if (url.pathname === "/api/usage") {
    const month = day().slice(0, 7);
    const { results } = await env.DB.prepare("SELECT a.user_id, u.nom, a.model, COUNT(*) AS n, SUM(a.input_tokens) AS inp, SUM(a.output_tokens) AS outp, SUM(a.images) AS img FROM ai_usage a LEFT JOIN users u ON u.id = a.user_id WHERE a.day LIKE ? GROUP BY a.user_id, a.model").bind(month + "%").all();
    return json({ month, items: results || [] });
  }
  return null;
}

/* ---------- IA (Claude) ---------- */
const MODELS = (env) => ({
  quick: env.MODEL_QUICK || "claude-haiku-5-5",
  default: env.MODEL_DEFAULT || "claude-sonnet-5-5",
  complex: env.MODEL_COMPLEX || env.MODEL_DEFAULT || "claude-sonnet-5-5",
});
const SENTINEL = "\u0001";

async function routeAI(env, req, url, u, ctx) {
  if (url.pathname !== "/api/ai" || req.method !== "POST") return null;
  const key = (env.ANTHROPIC_API_KEY || "").trim();
  if (!key) fail("no_key", "La clé API Claude n'est pas encore réglée sur le serveur (secret ANTHROPIC_API_KEY).", 503);
  const limit = parseInt(env.DAILY_AI_LIMIT || "200", 10);
  if (u.role !== "parent" && limit > 0) {
    const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM ai_usage WHERE user_id = ? AND day = ?").bind(u.id, day()).first();
    if (c && c.n >= limit) fail("rate_limited", `Limite du jour atteinte (${limit} demandes à l'IA). Reviens demain !`, 429);
  }
  const inp = await req.json().catch(() => null);
  if (!inp || !inp.input) fail("invalid_request", "Demande vide.");
  const tier = ["quick", "default", "complex"].includes(inp.tier) ? inp.tier : "default";
  const model = MODELS(env)[tier];
  const images = (Array.isArray(inp.images) ? inp.images : []).slice(0, 8).filter(s => typeof s === "string" && s.length < 8_000_000);
  const imgBlocks = images.map(data => ({ type: "image", source: { type: "base64", media_type: "image/jpeg", data } }));
  let messages;
  if (typeof inp.input === "string") messages = [{ role: "user", content: [...imgBlocks, { type: "text", text: inp.input }] }];
  else if (Array.isArray(inp.input)) {
    messages = [];
    for (const t of inp.input) {
      if (!t || !["user", "assistant"].includes(t.role) || !String(t.content || "").trim()) continue;
      const last = messages[messages.length - 1];
      if (last && last.role === t.role) last.content[0].text += "\n\n" + t.content;
      else messages.push({ role: t.role, content: [{ type: "text", text: String(t.content) }] });
    }
    if (!messages.length || messages[0].role !== "user" || messages[messages.length - 1].role !== "user") fail("invalid_request", "Conversation mal formée.");
    if (imgBlocks.length) messages[messages.length - 1].content.unshift(...imgBlocks);
  } else fail("invalid_request", "Demande mal formée.");

  const upstream = await fetch((env.ANTHROPIC_URL || "https://api.anthropic.com") + "/v1/messages", {
    method: "POST",
    headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({ model, max_tokens: tier === "quick" ? 4096 : 16000, messages, stream: true }),
  });
  if (!upstream.ok) {
    const t = await upstream.text().catch(() => "");
    console.log("anthropic error", upstream.status, t.slice(0, 500));
    if (upstream.status === 401 || upstream.status === 403) fail("bad_key", "La clé API Claude est refusée : vérifie-la dans Cloudflare.", 502);
    if (upstream.status === 429 || upstream.status === 529) fail("rate_limited", "L'IA est très sollicitée, réessaie dans une minute.", 429);
    if (upstream.status === 400 && /credit|billing/i.test(t)) fail("no_credit", "Plus de crédit sur le compte API Claude.", 502);
    if (upstream.status === 404 || /model/i.test(t)) fail("bad_model", "Modèle d'IA introuvable : vérifie MODEL_* dans wrangler.jsonc.", 502);
    fail("upstream_error", "L'IA n'a pas pu répondre (" + upstream.status + ").", 502);
  }

  const { readable, writable } = new TransformStream();
  const w = writable.getWriter();
  const usage = { input: 0, output: 0 };
  ctx.waitUntil((async () => {
    const reader = upstream.body.getReader(); const dec = new TextDecoder(); let buf = "";
    try {
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
          if (!line.startsWith("data:")) continue;
          let ev; try { ev = JSON.parse(line.slice(5)); } catch (e) { continue; }
          if (ev.type === "content_block_delta" && ev.delta && ev.delta.type === "text_delta") await w.write(enc.encode(ev.delta.text));
          else if (ev.type === "message_start" && ev.message && ev.message.usage) usage.input = (ev.message.usage.input_tokens || 0) + (ev.message.usage.cache_read_input_tokens || 0) + (ev.message.usage.cache_creation_input_tokens || 0);
          else if (ev.type === "message_delta") { if (ev.usage) usage.output = ev.usage.output_tokens || usage.output; if (ev.delta && ev.delta.stop_reason === "max_tokens") await w.write(enc.encode(SENTINEL + "TRUNC")); }
          else if (ev.type === "error") await w.write(enc.encode(SENTINEL + "ERR" + ((ev.error && ev.error.message) || "erreur")));
        }
      }
    } catch (e) {
      try { await w.write(enc.encode(SENTINEL + "ERRconnexion interrompue")); } catch (_) {}
    } finally {
      try { await w.close(); } catch (_) {}
      try { await env.DB.prepare("INSERT INTO ai_usage (user_id, day, model, input_tokens, output_tokens, images) VALUES (?, ?, ?, ?, ?, ?)").bind(u.id, day(), model, usage.input, usage.output, images.length).run(); } catch (_) {}
    }
  })());
  return new Response(readable, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}

/* ---------- installation (création des comptes) ---------- */
function page(title, body) {
  return new Response(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escH(title)}</title>
<style>body{font-family:system-ui,sans-serif;background:#f7f4ee;color:#1f1d1a;max-width:640px;margin:30px auto;padding:0 16px;line-height:1.5}h1{font-size:26px}.box{background:#fffdf9;border:1px solid #e7e1d6;border-radius:14px;padding:16px 18px;margin:14px 0}label{display:block;margin:8px 0 2px;font-size:14px;color:#5b574f}input{width:100%;box-sizing:border-box;padding:9px 11px;border:1px solid #d9d1c2;border-radius:9px;font:inherit}button{background:#1f5f53;color:#fff;border:0;border-radius:10px;padding:11px 18px;font:inherit;font-weight:600;cursor:pointer}.ok{background:#e3f0ec;border-color:#c5e0d8}.err{background:#fbe4e2;border-color:#f3cdc8}small{color:#8d887d}</style></head><body>${body}</body></html>`, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Frame-Options": "DENY" } });
}
async function routeInstall(env, req, url) {
  const token = url.searchParams.get("token") || "";
  if (!env.INSTALL_TOKEN || !safeEq(token, env.INSTALL_TOKEN)) return page("Installation", `<h1>Installation</h1><div class="box err">Lien d'installation invalide. Ajoute le secret <b>INSTALL_TOKEN</b> dans Cloudflare puis ouvre <code>/install?token=…</code>.</div>`);
  let msg = "";
  if (req.method === "POST") {
    const f = await req.formData();
    const done = [];
    for (const k of ["p", "e1", "e2", "e3"]) {
      const login = String(f.get(k + "_login") || "").trim().toLowerCase(), nom = String(f.get(k + "_nom") || "").trim(), pw = String(f.get(k + "_pw") || "");
      if (!login) continue;
      if (!/^[a-z0-9._@-]{2,60}$/.test(login)) { msg += `<div class="box err">Identifiant « ${escH(login)} » invalide (lettres, chiffres, . _ - @).</div>`; continue; }
      const exists = await env.DB.prepare("SELECT id FROM users WHERE login = ?").bind(login).first();
      if (!exists && pw.length < 6) { msg += `<div class="box err">Mot de passe trop court pour « ${escH(login)} » (6 caractères minimum).</div>`; continue; }
      const role = k === "p" ? "parent" : "eleve";
      if (exists) {
        if (pw) { if (pw.length < 6) { msg += `<div class="box err">Mot de passe trop court pour « ${escH(login)} ».</div>`; continue; } await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(await hashPassword(pw), exists.id).run(); await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(exists.id).run(); }
        if (nom) await env.DB.prepare("UPDATE users SET nom = ? WHERE id = ?").bind(nom, exists.id).run();
        done.push(`${escH(login)} (mis à jour)`);
      } else {
        await env.DB.prepare("INSERT INTO users (login, nom, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?)").bind(login, nom || login, role, await hashPassword(pw), nowIso()).run();
        done.push(`${escH(login)} (${role === "parent" ? "parent" : "élève"} créé)`);
      }
    }
    if (done.length) msg += `<div class="box ok">✅ ${done.join(", ")}.<br><a href="/">Ouvrir l'application →</a></div>`;
  }
  const { results } = await env.DB.prepare("SELECT login, nom, role FROM users ORDER BY role DESC, id").all();
  const list = (results || []).map(r => `<li><b>${escH(r.login)}</b> — ${escH(r.nom)} (${r.role === "parent" ? "parent" : "élève"})</li>`).join("");
  const block = (k, title, hint) => `<div class="box"><strong>${title}</strong><br><small>${hint}</small>
    <label>Identifiant</label><input name="${k}_login" autocomplete="off" autocapitalize="none"><label>Prénom</label><input name="${k}_nom" autocomplete="off"><label>Mot de passe</label><input name="${k}_pw" type="password" autocomplete="new-password"></div>`;
  return page("Installation — Crapule", `<h1>✏️ Crapule — comptes</h1>${msg}
  ${list ? `<div class="box"><strong>Comptes existants</strong><ul>${list}</ul><small>Pour changer un mot de passe, remets l'identifiant ci-dessous avec le nouveau mot de passe.</small></div>` : ""}
  <form method="post">${block("p", "👀 Compte parent", "Voit le suivi de chaque élève et la consommation de l'IA.")}${block("e1", "🎒 Élève 1", "")}${block("e2", "🎒 Élève 2 (facultatif)", "")}${block("e3", "🎒 Élève 3 (facultatif)", "")}<button>Enregistrer</button></form>`);
}

/* ---------- aiguillage ---------- */
export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => { try { await ensureSchema(env); await runReminders(env); } catch (e) { console.log("rappels", e && e.stack || e); } })());
  },
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    try {
      if (url.pathname === "/install" || url.pathname === "/install.php") { await ensureSchema(env); return await routeInstall(env, req, url); }
      if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
      await ensureSchema(env);
      if (req.method !== "GET" && req.method !== "HEAD") {
        const origin = req.headers.get("Origin");
        if (origin && new URL(origin).host !== url.host) fail("forbidden", "Origine refusée.", 403);
      }
      const a = await routeAuth(env, req, url); if (a) return a;
      const u = await currentUser(env, req);
      if (!u) fail("unauthenticated", "Connecte-toi.", 401);
      if (url.pathname === "/api/me") return json({ user: pub(u), ai: !!(env.ANTHROPIC_API_KEY || "").trim() });
      if (url.pathname === "/api/push/key") return json({ key: await vapidPublic(env), subs: await subsCount(env, u.id) });
      if (url.pathname === "/api/push/sub" && req.method === "POST") { const inp = await req.json().catch(() => ({})); try { await saveSub(env, u.id, inp.sub, req.headers.get("User-Agent")); } catch (e) { fail("invalid_argument", e.message); } return json({ ok: true }); }
      if (url.pathname === "/api/push/unsub" && req.method === "POST") { const inp = await req.json().catch(() => ({})); await dropSub(env, u.id, inp.endpoint); return json({ ok: true }); }
      if (url.pathname === "/api/push/test" && req.method === "POST") { const n = await pushUser(env, u.id, { title: "🦊 Coucou, c'est Crapule !", body: "Les rappels marchent sur ce téléphone.", url: "./", tag: "test" }); return json({ ok: n > 0, sent: n }); }
      return (await routeLib(env, req, url, u)) || (await routeDocs(env, req, url, u)) || (await routeParent(env, req, url, u)) || (await routeAI(env, req, url, u, ctx)) || fail("not_found", "Adresse inconnue.", 404);
    } catch (e) {
      if (e instanceof HttpError) return json({ code: e.code, message: e.message }, e.status);
      console.log("erreur", e && e.stack || e);
      return json({ code: "internal", message: "Erreur interne du serveur." }, 500);
    }
  },
};
