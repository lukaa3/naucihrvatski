/* ============================================================
   Pleter — cloud save
   Auth is handled entirely by Netlify Identity. This function
   never sees or stores a password; it only trusts the verified
   user that Netlify attaches to the request.
   ============================================================ */

const { getStore } = require("@netlify/blobs");

const MAX_SAVE_BYTES = 900000;   // ~900 KB per user

const json = (code, obj) => ({
  statusCode: code,
  headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  body: JSON.stringify(obj)
});

exports.handler = async (event, context) => {
  // Netlify populates this only when a valid Identity JWT was sent.
  // A forged or expired token simply never gets here.
  const user = context.clientContext && context.clientContext.user;
  if(!user || !user.sub){
    return json(401, { error: "NOT_SIGNED_IN" });
  }

  let store;
  try{ store = getStore("pleter-saves"); }
  catch(e){
    console.error("Blobs unavailable:", e && e.message);
    return json(500, { error: "STORAGE_UNAVAILABLE" });
  }

  const key = "user_" + user.sub;

  try{
    if(event.httpMethod === "GET"){
      const raw = await store.get(key);
      if(!raw) return json(200, { empty: true, email: user.email });
      const rec = JSON.parse(raw);
      return json(200, {
        empty: false,
        state: rec.state,
        updatedAt: rec.updatedAt || 0,
        email: user.email
      });
    }

    if(event.httpMethod === "POST"){
      let body;
      try{ body = JSON.parse(event.body || "{}"); }
      catch(e){ return json(400, { error: "BAD_JSON" }); }

      if(!body.state || typeof body.state !== "object"){
        return json(400, { error: "NO_STATE" });
      }

      const rec = { state: body.state, updatedAt: Date.now(), v: body.v || null };
      const payload = JSON.stringify(rec);

      if(payload.length > MAX_SAVE_BYTES){
        return json(413, { error: "TOO_LARGE" });
      }

      await store.set(key, payload);
      return json(200, { ok: true, updatedAt: rec.updatedAt });
    }

    if(event.httpMethod === "DELETE"){
      await store.delete(key);
      return json(200, { ok: true, deleted: true });
    }

    return json(405, { error: "Method not allowed" });

  }catch(err){
    console.error("Sync failure:", err && err.message);
    return json(500, { error: "SYNC_FAILED" });
  }
};
