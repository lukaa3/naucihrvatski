/* ============================================================
   Nauči hrvatski — Gemini proxy
   The API key lives in the GEMINI_API_KEY environment variable
   and never reaches the browser.
   ============================================================ */

// Tried in order. If Google 404s one (retired without notice, which happens),
// the next is tried automatically and remembered for this instance.
const MODEL_CHAIN     = ["gemini-3.6-flash", "gemini-3.5-flash", "gemini-2.5-flash"];
const DEFAULT_MODEL   = MODEL_CHAIN[0];
const ALLOWED_MODELS  = new Set([...MODEL_CHAIN, "gemini-3.1-flash-lite", "gemini-2.5-flash-lite"]);
let WORKING_MODEL     = null;   // cached once something succeeds

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

// Maps an upstream failure to a specific, safe explanation.
function classify(status, detail){
  const d = String(detail || "");
  if(/API key not valid|API_KEY_INVALID/i.test(d))
    return "KEY_INVALID: the GEMINI_API_KEY value is not a valid key. Check for a stray space or a deleted key, then redeploy.";
  if(/API key expired|API_KEY_EXPIRED/i.test(d))
    return "KEY_EXPIRED: this key has expired. Create a new one in Google AI Studio.";
  if(/SERVICE_DISABLED|has not been used in project|is disabled/i.test(d))
    return "API_DISABLED: the Generative Language API isn't enabled for this key's project. Enable it in Google Cloud, then wait a minute.";
  if(/PERMISSION_DENIED|caller does not have permission|API keys are not supported/i.test(d))
    return "PERMISSION: the key exists but isn't allowed to call this API. Check the key's API restrictions in Google Cloud.";
  if(/billing/i.test(d))
    return "BILLING: this project needs billing enabled.";
  if(/quota|RESOURCE_EXHAUSTED/i.test(d))
    return "QUOTA: this key has used up its quota. Free-tier limits reset daily at midnight Pacific time.";
  if(/not found|NOT_FOUND/i.test(d) || status === 404)
    return "MODEL: this key can't access that model.";
  if(status === 429) return "QUOTA: the free-tier quota for this model is used up. It resets daily at midnight Pacific time.";
  return "UPSTREAM_" + status + ": Gemini rejected the request. Full detail is in the Netlify function log.";
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
      const base = {
        ok: true,
        deployed: true,
        keyConfigured: !!process.env.GEMINI_API_KEY,
        originAllowed: originOk(h),
        originsConfigured: allowedOrigins(),
        model: DEFAULT_MODEL
      };
      // ?ping=1&live=1 spends one tiny call to prove the key actually works.
      if(q.live !== undefined && process.env.GEMINI_API_KEY){
        try{
          const r = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${DEFAULT_MODEL}:generateContent`, {
              method: "POST",
              headers: { "Content-Type": "application/json", "x-goog-api-key": process.env.GEMINI_API_KEY },
              body: JSON.stringify({
                contents: [{ role: "user", parts: [{ text: "hi" }] }],
                generationConfig: { maxOutputTokens: 256 }
              })
            });
          if(r.ok){ base.keyWorks = true; base.modelUsed = DEFAULT_MODEL; }
          else {
            let detail = "";
            try { const j = await r.json(); detail = (j.error && j.error.message) || ""; } catch(e){}
            console.error("Live key check failed:", r.status, detail);
            base.keyWorks = false;
            base.keyProblem = classify(r.status, detail);
          }
        }catch(e){
          base.keyWorks = false;
          base.keyProblem = "NETWORK: the function couldn't reach Google.";
        }
      }
      return json(200, base, origin);
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
        ? "Too fast. Wait a minute and try again."
        : "Daily limit for this site reached. Try again tomorrow."
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

  const send = (m, p) => fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": key },
      body: JSON.stringify(p)
    });

  try {
    // Candidates: what was asked for, then the chain, minus duplicates.
    const tried = [];
    const candidates = [WORKING_MODEL, model, ...MODEL_CHAIN]
      .filter(m => m && !tried.includes(m) && (tried.push(m), true));

    let res = null, used = null;
    for(const m of candidates){
      res = await send(m, payload);

      if(res.status === 400){                     // some models reject thinkingConfig
        const retry = JSON.parse(JSON.stringify(payload));
        delete retry.generationConfig.thinkingConfig;
        res = await send(m, retry);
      }

      // 404 = model retired. 429 = that model's free-tier quota is spent.
      // Both are worth retrying on the next model, since limits are per-model.
      if((res.status === 404 || res.status === 429) && m !== candidates[candidates.length - 1]){
        console.warn(`Model ${m} unavailable (${res.status}), falling back.`);
        continue;
      }
      used = m;
      break;
    }

    if(!used){
      console.error("Every model in the chain failed:", candidates.join(", "));
      return json(502, { error: "MODEL: none of the configured models are available. Update MODEL_CHAIN in chat.js." }, origin);
    }
    if(res.ok) WORKING_MODEL = used;

    if(!res.ok){
      let detail = "";
      try { const j = await res.json(); detail = (j.error && j.error.message) || ""; } catch(e){}
      console.error("Gemini error", res.status, detail);   // logged server-side only

      // Classify without echoing Google's raw text (it can contain project detail).
      return json(res.status === 429 ? 429 : 502, { error: classify(res.status, detail) }, origin);
    }

    const data = await res.json();
    const cand = (data.candidates || [])[0];
    const text = (((cand || {}).content || {}).parts || []).map(p => p.text || "").join("").trim();

    if(!text){
      const reason = cand && cand.finishReason;
      return json(502, {
        error: reason === "MAX_TOKENS" ? "The reply got cut off. Try again."
             : reason === "SAFETY"     ? "The reply was blocked by a safety filter."
             : "Empty reply from Gemini."
      }, origin);
    }

    return json(200, { text, model: used }, origin);

  } catch(err){
    console.error("Proxy failure:", err && err.message);
    return json(502, { error: "Could not reach Gemini." }, origin);
  }
};
