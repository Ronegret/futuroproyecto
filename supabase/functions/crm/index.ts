// RODD. Studio · CRM privado
// Toda la lectura/escritura del esquema `crm` pasa por esta función.
// La clave de acceso se guarda como hash con sal en crm.settings (o en el secreto ADMIN_KEY),
// nunca en el código ni en el navegador.
import postgres from "npm:postgres@3.4.4";

const DB_URL = Deno.env.get("SUPABASE_DB_URL")!;
const ENV_KEY = Deno.env.get("ADMIN_KEY") ?? "";
const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const RESEND_API_KEY = Deno.env.get("CRM_RESEND_API_KEY") ?? Deno.env.get("RESEND_API_KEY") ?? "";
const FROM = Deno.env.get("CRM_FROM_EMAIL") ?? "RODD. Studio <hola@avisos.rodrigonegrete.es>";
const REPLY_TO = Deno.env.get("CRM_REPLY_TO") ?? "";
const TOKEN_HOURS = 12;
const MAX_FAILS = 8; // por IP cada 15 minutos

const sql = postgres(DB_URL, {
  prepare: false,
  max: 3,
  types: {
    date: { to: 1082, from: [1082], serialize: (x: string) => x, parse: (x: string) => x },
    numeric: { to: 1700, from: [1700], serialize: (x: number) => String(x), parse: (x: string) => Number(x) },
  },
});

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, x-crm-token, authorization, apikey",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "content-type": "application/json" } });

// ---------- clave de acceso (hash con sal guardado en crm.settings) ----------
const enc = new TextEncoder();
let keyCache: { v: string; t: number } | null = null;
async function storedKey() {
  if (keyCache && Date.now() - keyCache.t < 60_000) return keyCache.v;
  const r = await sql`select value from crm.settings where key = 'admin_key'`;
  keyCache = { v: r[0]?.value ?? "", t: Date.now() };
  return keyCache.v;
}
async function sha256(s: string) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function keyOk(input: string) {
  if (ENV_KEY) return safeEqual(input, ENV_KEY);
  const [salt, hash] = (await storedKey()).split(":");
  if (!salt || !hash) return false;
  return safeEqual(await sha256(salt + input), hash);
}
async function configured() { return !!ENV_KEY || !!(await storedKey()); }

// ---------- firma de tokens ----------
async function hmac(msg: string) {
  const SIGN_SECRET = SERVICE + "|" + (ENV_KEY || (await storedKey()));
  const key = await crypto.subtle.importKey("raw", enc.encode(SIGN_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
  return btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function makeToken() {
  const exp = Date.now() + TOKEN_HOURS * 3600_000;
  return { token: `${exp}.${await hmac(String(exp))}`, exp };
}
async function checkToken(t: string | null) {
  if (!t) return false;
  const [exp, sig] = t.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEqual(sig, await hmac(exp));
}

// ---------- columnas permitidas ----------
const COLS: Record<string, string[]> = {
  clients: ["name", "company", "business_type", "sector", "email", "phone", "city", "website", "status", "source", "priority", "tags", "notes", "next_action", "next_action_date", "estimated_value"],
  projects: ["client_id", "title", "services", "agreement", "amount_total", "monthly_fee", "start_date", "due_date", "status", "progress", "deliverables", "notes"],
  payments: ["client_id", "project_id", "concept", "amount", "due_date", "paid_at", "status", "method", "invoice_number", "notes"],
  activities: ["client_id", "type", "content"],
};
function clean(table: string, row: Record<string, unknown>) {
  const out: Record<string, unknown> = {};
  for (const c of COLS[table]) {
    if (!(c in row)) continue;
    let v = row[c];
    if (v === "") v = null;
    if (c === "deliverables") v = sql.json((v as unknown[]) ?? []);
    if ((c === "tags" || c === "services") && v == null) v = [];
    out[c] = v;
  }
  return out;
}

async function loadAll() {
  const [clients, projects, payments, activities] = await Promise.all([
    sql`select * from crm.clients order by updated_at desc`,
    sql`select * from crm.projects order by coalesce(due_date, '2999-12-31') asc`,
    sql`select * from crm.payments order by coalesce(due_date, '2999-12-31') asc`,
    sql`select * from crm.activities order by created_at desc limit 800`,
  ]);
  return { clients, projects, payments, activities };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  let body: Record<string, any> = {};
  try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
  const action = String(body.action ?? "");
  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || "desconocida";

  try {
    // ---------- login ----------
    if (action === "login") {
      if (!(await configured())) return json({ error: "not_configured" }, 503);
      const [{ n }] = await sql`select count(*)::int as n from crm.login_attempts where ip = ${ip} and ok = false and at > now() - interval '15 minutes'`;
      if (n >= MAX_FAILS) return json({ error: "locked", retry_minutes: 15 }, 429);
      const ok = await keyOk(String(body.key ?? ""));
      await sql`insert into crm.login_attempts (ip, ok) values (${ip}, ${ok})`;
      await sql`delete from crm.login_attempts where at < now() - interval '30 days'`;
      if (!ok) {
        await new Promise((r) => setTimeout(r, 600));
        return json({ error: "bad_key", left: Math.max(0, MAX_FAILS - n - 1) }, 401);
      }
      return json({ ...(await makeToken()), email_enabled: !!RESEND_API_KEY });
    }

    // ---------- todo lo demás requiere token ----------
    if (!(await checkToken(req.headers.get("x-crm-token")))) return json({ error: "unauthorized" }, 401);

    if (action === "change_key") {
      if (ENV_KEY) return json({ error: "managed_by_secret" }, 400);
      if (!(await keyOk(String(body.current ?? "")))) return json({ error: "bad_key" }, 401);
      const nk = String(body.next ?? "");
      if (nk.length < 6) return json({ error: "too_short" }, 400);
      const salt = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
      await sql`update crm.settings set value = ${salt + ":" + (await sha256(salt + nk))}, updated_at = now() where key = 'admin_key'`;
      keyCache = null;
      return json({ ok: true, ...(await makeToken()) });
    }

    if (action === "data") return json({ ...(await loadAll()), email_enabled: !!RESEND_API_KEY });

    if (action === "save") {
      const table = String(body.table);
      if (!COLS[table]) return json({ error: "table" }, 400);
      const row = clean(table, body.row ?? {});
      const id = body.row?.id;
      let res;
      if (id) {
        if (!Object.keys(row).length) return json({ error: "empty" }, 400);
        res = await sql`update ${sql("crm." + table)} set ${sql(row)} where id = ${id} returning *`;
      } else {
        res = await sql`insert into ${sql("crm." + table)} ${sql(row)} returning *`;
      }
      return json({ row: res[0] });
    }

    if (action === "remove") {
      const table = String(body.table);
      if (!COLS[table]) return json({ error: "table" }, 400);
      await sql`delete from ${sql("crm." + table)} where id = ${body.id}`;
      return json({ ok: true });
    }

    if (action === "import") {
      // restaurar copia de seguridad (JSON exportado desde el panel)
      const d = body.data ?? {};
      let n = 0;
      await sql.begin(async (tx) => {
        for (const t of ["clients", "projects", "payments", "activities"]) {
          for (const r of d[t] ?? []) {
            const row: Record<string, unknown> = { id: r.id, ...clean(t, r) };
            if (r.created_at) row.created_at = r.created_at;
            await tx`insert into ${tx("crm." + t)} ${tx(row)} on conflict (id) do nothing`;
            n++;
          }
        }
      });
      return json({ ok: true, rows: n });
    }

    if (action === "email") {
      if (!RESEND_API_KEY) return json({ error: "email_not_configured" }, 501);
      const to = String(body.to ?? "").trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return json({ error: "bad_to" }, 400);
      const subject = String(body.subject ?? "").slice(0, 200);
      const text = String(body.text ?? "").slice(0, 10000);
      const html = `<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.6;color:#111">${text
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\n/g, "<br>")}</div>`;
      const r = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { authorization: `Bearer ${RESEND_API_KEY}`, "content-type": "application/json" },
        body: JSON.stringify({ from: FROM, to: [to], subject, text, html, ...(REPLY_TO ? { reply_to: REPLY_TO } : {}) }),
      });
      const out = await r.json().catch(() => ({}));
      if (!r.ok) return json({ error: "send_failed", detail: out?.message ?? r.status }, 502);
      if (body.payment_id) await sql`update crm.payments set reminders_sent = reminders_sent + 1, last_reminder_at = now() where id = ${body.payment_id}`;
      if (body.client_id) await sql`insert into crm.activities (client_id, type, content) values (${body.client_id}, 'email', ${"Correo enviado: " + subject})`;
      return json({ ok: true, id: out?.id });
    }

    return json({ error: "action" }, 400);
  } catch (e) {
    console.error(e);
    return json({ error: "server", detail: String((e as Error)?.message ?? e).slice(0, 200) }, 500);
  }
});
