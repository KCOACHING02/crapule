/*
 * Lecture des livres en arrière-plan : le téléphone envoie les photos, le serveur les lit
 * (Mistral OCR) chaque minute et range le texte dans la bibliothèque, même appli fermée.
 */
const JOB_SCHEMA = [
  "CREATE TABLE IF NOT EXISTS book_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, book TEXT NOT NULL, n INTEGER NOT NULL, img TEXT, txt TEXT, status TEXT NOT NULL DEFAULT 'wait', tries INTEGER NOT NULL DEFAULT 0, user_id INTEGER NOT NULL, at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS book_jobs_book ON book_jobs (book, status)",
];
let ready = false;
async function jobsSchema(env) { if (ready) return; for (const s of JOB_SCHEMA) await env.DB.prepare(s).run(); ready = true; }

const STOP = new Set("les des une un le la de du et en à au aux pour par sur dans avec est sont qui que quoi dont où ce cet cette ces son sa ses leur leurs nous vous ils elles il elle on ne pas plus moins être avoir fait faire peut doit entre comme mais ou donc car ainsi aussi tout tous toute toutes très bien leurs lors après avant chez sans sous vers été cela celui celle ceux elles être était sera soit fois deux trois page chapitre partie exemple exemples selon également notamment afin alors quand comment pourquoi lorsque".split(" "));
const norm = t => String(t || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
const tokens = t => (norm(t).match(/[a-z0-9]{4,}/g) || []).filter(w => !STOP.has(w));
const keywords = (text, n = 70) => { const f = {}; for (const w of tokens(text)) f[w] = (f[w] || 0) + 1; return Object.entries(f).sort((a, b) => b[1] - a[1]).slice(0, n); };
const chunkTitle = t => t.split("\n").map(x => x.replace(/^#+\s*/, "").trim()).find(x => x.length > 3 && x.length < 90) || t.slice(0, 60);
const upsert = (env, id, data) => env.DB.prepare("INSERT INTO docs (user_id, id, data, updated_at) VALUES (0, ?, ?, ?) ON CONFLICT (user_id, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at").bind(id, JSON.stringify(data), new Date().toISOString()).run();

export async function routeJobs(env, req, url, u, fail, json) {
  if (url.pathname === "/api/jobs/run" && req.method === "POST") {
    await jobsSchema(env);
    try { const n = await runBookJobs(env, 3); return json({ ok: true, assembled: n }); }
    catch (e) { try { await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('jobs:err', ?)").bind(String(e && e.message || e).slice(0, 200)).run(); } catch (x) {} return json({ ok: false, err: String(e && e.message || e) }); }
  }
  if (url.pathname !== "/api/jobs") return null;
  await jobsSchema(env);
  if (req.method === "GET") {
    const { results } = await env.DB.prepare("SELECT book, status, COUNT(*) AS c, MAX(n) AS mx FROM book_jobs GROUP BY book, status").all();
    const by = {};
    for (const r of results || []) { const b = by[r.book] = by[r.book] || { wait: 0, done: 0, err: 0, maxN: 0 }; b[r.status === "run" ? "wait" : r.status] = (b[r.status === "run" ? "wait" : r.status] || 0) + r.c; b.maxN = Math.max(b.maxN, r.mx || 0); }
    const m = await env.DB.prepare("SELECT k, v FROM meta WHERE k IN ('jobs:run', 'jobs:err')").all();
    const meta = {}; for (const r of m.results || []) meta[r.k] = r.v;
    return json({ items: by, lastRun: meta["jobs:run"] || null, lastErr: meta["jobs:err"] || null });
  }
  if (req.method === "POST") {
    if (!(env.MISTRAL_API_KEY || "").trim()) fail("no_ocr", "Lecture Mistral non configurée.", 503);
    const inp = await req.json().catch(() => null);
    const book = String(inp && inp.book || ""), n = parseInt(inp && inp.n, 10), img = String(inp && inp.img || "");
    if (!/^[A-Za-z0-9]{3,40}$/.test(book) || !(n > 0) || img.length < 100 || img.length > 1_900_000) fail("invalid_argument", "Photo invalide ou trop lourde.");
    const idx = await env.DB.prepare("SELECT 1 FROM docs WHERE user_id = 0 AND id = ?").bind("book_" + book).first();
    if (!idx) fail("not_found", "Livre introuvable.", 404);
    const dup = await env.DB.prepare("SELECT id FROM book_jobs WHERE book = ? AND n = ?").bind(book, n).first();
    if (dup) return json({ ok: true, dup: true });
    await env.DB.prepare("INSERT INTO book_jobs (book, n, img, status, user_id, at) VALUES (?, ?, ?, 'wait', ?, ?)").bind(book, n, img, u.id, Date.now()).run();
    return json({ ok: true });
  }
  if (false) {}
  if (req.method === "DELETE") {
    const book = url.searchParams.get("book") || "";
    await env.DB.prepare("DELETE FROM book_jobs WHERE book = ?").bind(book).run();
    return json({ ok: true });
  }
  return null;
}

async function ocrOne(env, b64) {
  const key = (env.MISTRAL_API_KEY || "").trim();
  const r = await fetch((env.MISTRAL_URL || "https://api.mistral.ai") + "/v1/ocr", { method: "POST", headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
    body: JSON.stringify({ model: env.MISTRAL_OCR_MODEL || "mistral-ocr-latest", document: { type: "image_url", image_url: "data:image/jpeg;base64," + b64 } }) });
  if (!r.ok) throw new Error("mistral " + r.status);
  const j = await r.json();
  return (j.pages || []).map(p => String(p.markdown || "").replace(/!\[[^\]]*\]\([^)]*\)/g, "").trim()).join("\n\n");
}

/* Appelé chaque minute par le cron. */
export async function runBookJobs(env, max = 8) {
  if (!(env.MISTRAL_API_KEY || "").trim()) return 0;
  await jobsSchema(env);
  const now = Date.now();
  try { await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('jobs:run', ?)").bind(new Date(now).toISOString()).run(); } catch (x) {}
  await env.DB.prepare("UPDATE book_jobs SET status = 'wait' WHERE status = 'run' AND at < ?").bind(now - 5 * 60000).run();
  const { results: rows } = await env.DB.prepare("SELECT id, user_id FROM book_jobs WHERE status = 'wait' ORDER BY id LIMIT ?").bind(max).all();
  if (rows && rows.length) {
    await env.DB.prepare(`UPDATE book_jobs SET status = 'run', at = ? WHERE id IN (${rows.map(() => "?").join(",")})`).bind(now, ...rows.map(r => r.id)).run();
    let i = 0; const users = {};
    const worker = async () => {
      while (i < rows.length) {
        const r = rows[i++];
        try {
          const im = await env.DB.prepare("SELECT img FROM book_jobs WHERE id = ?").bind(r.id).first();
          if (!im || !im.img) throw new Error("photo absente");
          const txt = await ocrOne(env, im.img);
          await env.DB.prepare("UPDATE book_jobs SET status = 'done', txt = ?, img = NULL WHERE id = ?").bind(txt, r.id).run();
          users[r.user_id] = (users[r.user_id] || 0) + 1;
        } catch (e) {
          console.log("ocr job", r.id, e && e.message);
          try { await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('jobs:err', ?)").bind(new Date().toISOString().slice(11, 16) + " " + String(e && e.message || e).slice(0, 200)).run(); } catch (x) {}
          await env.DB.prepare("UPDATE book_jobs SET tries = tries + 1, status = CASE WHEN tries >= 3 THEN 'err' ELSE 'wait' END, at = ? WHERE id = ?").bind(Date.now(), r.id).run();
        }
      }
    };
    await Promise.all([worker(), worker(), worker()]);
    for (const [uid, n] of Object.entries(users)) { try { await env.DB.prepare("INSERT INTO ai_usage (user_id, day, model, input_tokens, output_tokens, images) VALUES (?, ?, 'mistral-ocr', 0, 0, ?)").bind(+uid, new Date().toISOString().slice(0, 10), n).run(); } catch (e) {} }
  }
  return await assemble(env);
}

/* Range le texte des pages lues dans le livre, une fois toutes ses photos lues. */
async function assemble(env) {
  const { results: books } = await env.DB.prepare("SELECT book FROM book_jobs GROUP BY book HAVING SUM(CASE WHEN status IN ('wait','run') THEN 1 ELSE 0 END) = 0 AND SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) > 0").all();
  let made = 0;
  for (const { book } of books || []) {
    const ir = await env.DB.prepare("SELECT data FROM docs WHERE user_id = 0 AND id = ?").bind("book_" + book).first();
    if (!ir) { await env.DB.prepare("DELETE FROM book_jobs WHERE book = ?").bind(book).run(); continue; }
    const idx = JSON.parse(ir.data); idx.chunks = idx.chunks || []; idx.chars = idx.chars || 0;
    const { results: pages } = await env.DB.prepare("SELECT n, txt FROM book_jobs WHERE book = ? AND status = 'done' ORDER BY n").bind(book).all();
    let buf = "", bufPage = null, maxN = idx.pages || 0;
    const flush = async (force) => {
      while (buf.length >= 12000 || (force && buf.trim())) {
        let cut = Math.min(buf.length, 12000);
        if (buf.length > 12000) { const k = buf.lastIndexOf("\n\n", cut); if (k > 7000) cut = k; }
        const t = buf.slice(0, cut).trim(); buf = buf.slice(cut);
        if (t) { const n = idx.chunks.length; await upsert(env, `bkc_${book}_${n}`, { t }); idx.chunks.push({ n, titre: chunkTitle(t), p: bufPage, kw: keywords(t, 70) }); idx.chars += t.length; made++; }
        bufPage = null; if (!buf.trim()) { buf = ""; break; }
      }
    };
    for (const p of pages || []) { if (bufPage == null) bufPage = p.n; buf += (p.txt || "") + "\n\n"; maxN = Math.max(maxN, p.n); if (buf.length >= 12000) await flush(false); }
    await flush(true);
    idx.pages = maxN; delete idx.enCours;
    const { results: errs } = await env.DB.prepare("SELECT COUNT(*) AS c FROM book_jobs WHERE book = ? AND status = 'err'").bind(book).all();
    idx.illisibles = (idx.illisibles || 0) + ((errs && errs[0] && errs[0].c) || 0);
    await upsert(env, "book_" + book, idx);
    await env.DB.prepare("DELETE FROM book_jobs WHERE book = ?").bind(book).run();
  }
  return made;
}
