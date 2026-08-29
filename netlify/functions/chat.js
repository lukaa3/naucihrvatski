/* ============================================================
   Pleter — Gemini proxy
   The API key lives in the GEMINI_API_KEY environment variable
   and never reaches the browser.
   ============================================================ */

const DEFAULT_MODEL   = "gemini-2.5-flash";
const ALLOWED_MODELS  = new Set(["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-3.5-flash"]);

// --- abuse limits -------------------------------------------------
const MAX_MESSAGES     = 40;      // turns in one conversation
const MAX_TOTAL_CHARS  = 24000;   // total prompt size
const MAX_OUTPUT       = 4096;
const WINDOW_MS        = 60 * 1000;
const MAX_PER_WINDOW   = 20;      // requests per IP per minute
const MAX_PER_DAY      = 400;     // requests per IP per day

// Best-effort only: serverless instances are recycled, so this slows
// casual abuse rather than stopping a determined attacker.
const minute = new Map();
const day    = new Map();

function rateLimit(ip){
  const now = Date.now();
  const m = minute.get(ip) || { n: 0, t: now };
  if(now - m.t > WINDOW_MS){ m.n = 0; m.t = now; }
  m.n++; minute.set(ip, m);
  if(m.n > MAX_PER_WINDOW) return "minute";

  const d = day.get(ip) || { n: 0, t: now };
  if(now - d.t > 86400000){ d.n = 0; d.t = now; }
  d.n++; day.set(ip, d);
  if(d.n > MAX_PER_DAY) return "day";

  if(minute.size > 5000) minute.clear();
  if(day.size > 5000) day.clear();
  return null;
}

function allowedOrigins(){
  const list = [];
  if(process.env.ALLOWED_ORIGIN) list.push(...process.env.ALLOWED_ORIGIN.split(",").map(s => s.trim()));
  if(process.env.URL) list.push(process.env.URL);           // Netlify sets these
  if(process.env.DEPLOY_PRIME_URL) list.push(process.env.DEPLOY_PRIME_URL);
  if(process.env.DEPLOY_URL) list.push(process.env.DEPLOY_URL);
  return list.filter(Boolean);
}

function originOk(headers){
  const allow = allowedOrigins();
  if(!allow.length) return true;                            // nothing configured: don't lock the owner out
  const src = headers.origin || headers.Origin || headers.referer || headers.Referer || "";
  if(!src) return false;
  return allow.some(a => { try { return new URL(src).origin === new URL(a).origin; } catch(e){ return false; } });
}

const json = (code, obj, origin) => ({
  statusCode: code,
  headers: {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Cache-Control": "no-store"
  },
  body: JSON.stringify(obj)
});

exports.handler = async (event) => {
  const h = event.headers || {};
  const origin = h.origin || h.Origin || "";

  if(event.httpMethod === "OPTIONS") return json(204, {}, origin);

  // Health check. Reports whether the function is deployed, whether a key is
  // configured, and whether this origin passes — without exposing the key.
  if(event.httpMethod === "GET"){
    const q = event.queryStringParameters || {};
    if(q.ping !== undefined){
      return json(200, {
        ok: true,
        deployed: true,
        keyConfigured: !!process.env.GEMINI_API_KEY,
        originAllowed: originOk(h),
        originsConfigured: allowedOrigins(),
        model: DEFAULT_MODEL
      }, origin);
    }
    return json(405, { error: "Method not allowed" }, origin);
  }

  if(event.httpMethod !== "POST") return json(405, { error: "Method not allowed" }, origin);

  if(!originOk(h)) return json(403, { error: "Forbidden" }, origin);

  const key = process.env.GEMINI_API_KEY;
  if(!key){
    console.error("GEMINI_API_KEY is not set in the Netlify environment.");
    return json(500, { error: "Server is not configured yet." }, origin);
  }

  const ip = h["x-nf-client-connection-ip"] || h["client-ip"] || h["x-forwarded-for"] || "unknown";
  const limited = rateLimit(String(ip).split(",")[0].trim());
  if(limited){
    return json(429, {
      error: limited === "minute"
        ? "Prebrzo. Pričekaj minutu."
        : "Dnevni limit je dosegnut. Pokušaj sutra."
    }, origin);
  }

  // ---- validate input ----
  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch(e){ return json(400, { error: "Bad JSON" }, origin); }

  const system   = typeof body.system === "string" ? body.system : "";
  const messages = Array.isArray(body.messages) ? body.messages : null;
  const model    = ALLOWED_MODELS.has(body.model) ? body.model : DEFAULT_MODEL;
  const maxOut   = Math.min(MAX_OUTPUT, Math.max(256, Number(body.maxTokens) || 2048));

  if(!messages || !messages.length) return json(400, { error: "No messages" }, origin);
  if(messages.length > MAX_MESSAGES) return json(400, { error: "Conversation too long" }, origin);

  let total = system.length;
  for(const m of messages){
    if(!m || typeof m.content !== "string") return json(400, { error: "Bad message" }, origin);
    total += m.content.length;
  }
  if(total > MAX_TOTAL_CHARS) return json(413, { error: "Prompt too large" }, origin);

  // ---- call Gemini ----
  const payload = {
    system_instruction: system ? { parts: [{ text: system }] } : undefined,
    contents: messages.map(m => ({
      role: m.role === "assistant" || m.role === "model" ? "model" : "user",
      parts: [{ text: m.content }]
    })),
    generationConfig: {
      maxOutputTokens: maxOut,
      temperature: typeof body.temperature === "number" ? Math.min(1.5, Math.max(0, body.temperature)) : 0.85,
      thinkingConfig: { thinkingBudget: 0 }
    }
  };

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
  const send = p => fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-goog-api-key": key },
    body: JSON.stringify(p)
  });

  try {
    let res = await send(payload);

    if(res.status === 400){                       // some models reject thinkingConfig
      const retry = JSON.parse(JSON.stringify(payload));
      delete retry.generationConfig.thinkingConfig;
      res = await send(retry);
    }

    if(!res.ok){
      let detail = "";
      try { const j = await res.json(); detail = (j.error && j.error.message) || ""; } catch(e){}
      console.error("Gemini error", res.status, detail);   // logged server-side only

      // Never echo Google's message back — it can contain key or project detail.
      if(res.status === 429) return json(429, { error: "Gemini je preopterećen. Pokušaj za koju minutu." }, origin);
      if(res.status === 400 || res.status === 403) return json(502, { error: "Upstream rejected the request." }, origin);
      if(res.status === 404) return json(502, { error: "Model nije dostupan." }, origin);
      return json(502, { error: "Upstream error." }, origin);
    }

    const data = await res.json();
    const cand = (data.candidates || [])[0];
    const text = (((cand || {}).content || {}).parts || []).map(p => p.text || "").join("").trim();

    if(!text){
      const reason = cand && cand.finishReason;
      return json(502, {
        error: reason === "MAX_TOKENS" ? "Odgovor je predugačak — pokušaj ponovno."
             : reason === "SAFETY"     ? "Odgovor je blokiran."
             : "Prazan odgovor."
      }, origin);
    }

    return json(200, { text, model }, origin);

  } catch(err){
    console.error("Proxy failure:", err && err.message);
    return json(502, { error: "Nije uspjelo povezivanje s Geminijem." }, origin);
  }
};
