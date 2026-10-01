const APP_VERSION = "2026.10.01.7";
const SESSION_COOKIE = "__Host-ai_bot_manager";
const SESSION_SECONDS = 12 * 60 * 60;
const attempts = new Map();

const ROLES = {
  super_admin: { label: "Super Admin", groups: ["run-haven", "confidence"] },
  run_haven_admin: { label: "Run/Haven Admin", groups: ["run-haven"] },
  confidence_admin: { label: "Confidence Admin", groups: ["confidence"] }
};

const BOTS = [
  {
    id: "topex-search",
    name: "Topex Search Bot",
    description: "Run Energy and Topex Quickbase search assistant.",
    group: "run-haven",
    repository: "ianzgreig-ux/topex-search-bot",
    liveUrl: "https://topex.rundata.workers.dev/"
  },
  {
    id: "glues-n-tools",
    name: "Glues N Tools Chatbot",
    description: "Shopify product, inventory and product-document assistant.",
    group: "run-haven",
    repository: "ianzgreig-ux/glues-n-tools-chatbot",
    liveUrl: "https://glues-n-tools-chatbot.rundata.workers.dev/"
  },
  {
    id: "confidence-schedule",
    name: "Confidence Schedule and SmartSch",
    description: "Confidence Bar office, practitioner and training schedule assistant.",
    group: "confidence",
    repository: "ianzgreig-ux/confidence-office-schedule",
    liveUrl: "https://confidence.iangreig.workers.dev/"
  }
];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname === "/") return html(HTML);
      if (request.method === "GET" && url.pathname === "/api/health") {
        return json({ ok: true, service: "AI Bot Manager", version: APP_VERSION });
      }
      if (request.method === "POST" && url.pathname === "/api/login") return login(request, env);
      if (request.method === "POST" && url.pathname === "/api/logout") return logout(request);
      if (request.method === "GET" && url.pathname === "/api/session") {
        const session = await readSession(request, env);
        return json(session ? publicSession(session) : { authenticated: false });
      }
      if (request.method === "GET" && url.pathname === "/api/bots") {
        const session = await requireSession(request, env);
        return json({ role: publicSession(session), bots: allowedBots(session.role) });
      }
      if (request.method === "POST" && url.pathname === "/api/change-requests") {
        return createChangeRequest(request, env);
      }
      return json({ error: "Not found." }, 404);
    } catch (error) {
      console.error(error);
      return json({ error: error.publicMessage || "Something went wrong." }, error.status || 500);
    }
  }
};

async function login(request, env) {
  sameOrigin(request);
  if (!request.headers.get("content-type")?.includes("application/json")) throw publicError("Enter a six-digit PIN.", 415);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  cleanAttempts(now);
  const prior = attempts.get(ip);
  if (prior && prior.count >= 5 && prior.until > now) throw publicError("Too many incorrect attempts. Try again in 15 minutes.", 429);
  const raw = await request.text();
  if (raw.length > 250) throw publicError("Enter a six-digit PIN.", 400);
  let body;
  try { body = JSON.parse(raw); } catch { throw publicError("Enter a six-digit PIN.", 400); }
  const pin = String(body.pin || "").trim();
  const name = String(body.name || "").trim().slice(0, 60);
  if (!/^\d{6}$/.test(pin)) throw publicError("Enter a six-digit PIN.", 400);

  const role = await identifyRole(pin, env);
  if (!role) {
    attempts.set(ip, { count: (prior?.count || 0) + 1, until: prior?.until || now + 15 * 60 * 1000 });
    throw publicError("Incorrect PIN.", 401);
  }
  attempts.delete(ip);
  const issued = Math.floor(now / 1000);
  const payload = { role, name: name || ROLES[role].label, iat: issued, exp: issued + SESSION_SECONDS, nonce: crypto.randomUUID() };
  const token = await signPayload(payload, env);
  const response = json(publicSession(payload));
  response.headers.set("Set-Cookie", SESSION_COOKIE + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + SESSION_SECONDS);
  return response;
}

function logout(request) {
  sameOrigin(request);
  const response = json({ authenticated: false });
  response.headers.set("Set-Cookie", SESSION_COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
  return response;
}

async function createChangeRequest(request, env) {
  sameOrigin(request);
  const session = await requireSession(request, env);
  const contentType = request.headers.get("content-type") || "";
  let body;
  let screenshots = [];
  if (contentType.includes("multipart/form-data")) {
    const form = await request.formData();
    body = { botId: form.get("botId"), request: form.get("request") };
    screenshots = form.getAll("screenshots").filter(file => file && typeof file === "object" && file.size);
  } else {
    body = await request.json();
  }
  const bot = BOTS.find(item => item.id === String(body.botId || ""));
  if (!bot || !allowedBots(session.role).some(item => item.id === bot.id)) throw publicError("You do not have access to that chatbot.", 403);
  const requestText = String(body.request || "").trim();
  if (requestText.length < 10) throw publicError("Please provide a little more detail about the requested change.", 400);
  if (requestText.length > 6000) throw publicError("Please keep the request under 6,000 characters.", 400);
  if (!env.GITHUB_TOKEN) throw publicError("GitHub request creation has not been connected yet. Ask the Super Admin to add the GitHub token in Cloudflare.", 503);
  if (screenshots.length > 5) throw publicError("You can attach up to five screenshots.", 400);
  if (screenshots.length && !env.REQUEST_FILES) throw publicError("Screenshot storage is not connected yet.", 503);

  const allowedImageTypes = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
  for (const file of screenshots) {
    if (!allowedImageTypes.has(file.type)) throw publicError("Screenshots must be PNG, JPG, WEBP or GIF files.", 400);
    if (file.size > 5 * 1024 * 1024) throw publicError("Each screenshot must be 5 MB or smaller.", 400);
  }
  const requestId = crypto.randomUUID();
  const storedScreenshots = [];
  try {
    for (let index = 0; index < screenshots.length; index++) {
      const file = screenshots[index];
      const extension = file.type === "image/png" ? "png" : file.type === "image/jpeg" ? "jpg" : file.type === "image/webp" ? "webp" : "gif";
      const key = "requests/" + requestId + "/screenshot-" + (index + 1) + "." + extension;
      await env.REQUEST_FILES.put(key, file.stream(), { httpMetadata: { contentType: file.type }, customMetadata: { originalName: String(file.name || "screenshot").slice(0, 120), botId: bot.id, requestedBy: session.name } });
      storedScreenshots.push({ key, name: String(file.name || "Screenshot " + (index + 1)).slice(0, 120) });
    }
  } catch (error) {
    await Promise.all(storedScreenshots.map(item => env.REQUEST_FILES.delete(item.key).catch(() => {})));
    console.error("Screenshot storage error", error);
    throw publicError("The screenshots could not be stored. Please try again.", 502);
  }

  const titleText = requestText.split(/\n/)[0].replace(/\s+/g, " ").slice(0, 90);
  const issueBody = [
    "## Requested change",
    requestText,
    "",
    "## Request details",
    "- Bot: " + bot.name,
    "- Requested by: " + session.name,
    "- Access role: " + ROLES[session.role].label,
    "- Submitted through: AI Bot Manager v" + APP_VERSION,
    "- Screenshots: " + (storedScreenshots.length ? storedScreenshots.map(item => item.name).join(", ") : "None"),
    "",
    storedScreenshots.length ? "<!-- bot-manager-request-id:" + requestId + ";r2-keys:" + storedScreenshots.map(item => item.key).join("|") + " -->" : "",
    "",
    "> This request has not been deployed. The submitting user will review the proposed change before approving deployment."
  ].join("\n");

  const response = await fetch("https://api.github.com/repos/" + bot.repository + "/issues", {
    method: "POST",
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": "Bearer " + env.GITHUB_TOKEN,
      "Content-Type": "application/json",
      "User-Agent": "ai-bot-manager",
      "X-GitHub-Api-Version": "2022-11-28"
    },
    body: JSON.stringify({ title: "Change request: " + titleText, body: issueBody, labels: ["bot-change-request"] })
  });
  const responseText = await response.text();
  let result;
  try {
    result = JSON.parse(responseText);
  } catch {
    console.error("GitHub returned non-JSON", response.status, responseText.slice(0, 300));
    throw publicError("GitHub returned an unexpected response. Check the GitHub token and repository access.", 502);
  }
  if (!response.ok) {
    await Promise.all(storedScreenshots.map(item => env.REQUEST_FILES.delete(item.key).catch(() => {})));
    console.error("GitHub issue error", response.status, result);
    throw publicError(response.status === 404
      ? "The GitHub connection cannot access this repository or its Issues feature."
      : response.status === 401
        ? "The GitHub token is invalid or has expired."
        : response.status === 403
          ? "The GitHub token does not have permission to create Issues in this repository."
          : "GitHub could not create the change request.", 502);
  }
  return json({ ok: true, issueNumber: result.number, title: result.title, screenshotCount: storedScreenshots.length });
}

function allowedBots(role) {
  const groups = ROLES[role]?.groups || [];
  return BOTS.filter(bot => groups.includes(bot.group));
}

function publicSession(session) {
  return { authenticated: true, role: session.role, roleLabel: ROLES[session.role].label, name: session.name, expiresAt: new Date(session.exp * 1000).toISOString() };
}

async function identifyRole(pin, env) {
  const configured = [
    ["super_admin", env.SUPER_ADMIN_PIN],
    ["run_haven_admin", env.RUN_HAVEN_ADMIN_PIN],
    ["confidence_admin", env.CONFIDENCE_ADMIN_PIN]
  ];
  for (const [role, expected] of configured) {
    if (typeof expected === "string" && /^\d{6}$/.test(expected) && await safeEqual(pin, expected)) return role;
  }
  return null;
}

async function safeEqual(left, right) {
  const [a, b] = await Promise.all([digest(left), digest(right)]);
  let difference = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) difference |= (a[i % a.length] || 0) ^ (b[i % b.length] || 0);
  return difference === 0;
}

async function digest(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

async function sessionKey(env) {
  if (!env.SESSION_SECRET || String(env.SESSION_SECRET).length < 24) throw publicError("The Bot Manager session secret is not configured.", 503);
  return crypto.subtle.importKey("raw", new TextEncoder().encode("ai-bot-manager-v1\0" + env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function signPayload(payload, env) {
  const encoded = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = base64url(await crypto.subtle.sign("HMAC", await sessionKey(env), new TextEncoder().encode(encoded)));
  return encoded + "." + signature;
}

async function readSession(request, env) {
  try {
    const item = (request.headers.get("Cookie") || "").split(";").map(v => v.trim()).find(v => v.startsWith(SESSION_COOKIE + "="));
    if (!item) return null;
    const token = item.slice(SESSION_COOKIE.length + 1);
    const [encoded, signature, extra] = token.split(".");
    if (!encoded || !signature || extra || token.length > 1500) return null;
    const valid = await crypto.subtle.verify("HMAC", await sessionKey(env), unbase64url(signature), new TextEncoder().encode(encoded));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(unbase64url(encoded)));
    const now = Math.floor(Date.now() / 1000);
    if (!ROLES[payload.role] || !Number.isInteger(payload.iat) || !Number.isInteger(payload.exp) || payload.exp <= now || payload.iat > now + 30 || payload.exp - payload.iat !== SESSION_SECONDS) return null;
    return payload;
  } catch { return null; }
}

async function requireSession(request, env) {
  const session = await readSession(request, env);
  if (!session) throw publicError("Your session has expired. Please sign in again.", 401);
  return session;
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) throw publicError("Open the Bot Manager directly to continue.", 403);
}

function cleanAttempts(now) {
  for (const [key, value] of attempts) if (value.until <= now) attempts.delete(key);
  if (attempts.size > 10000) attempts.delete(attempts.keys().next().value);
}

function base64url(value) {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unbase64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}

function publicError(message, status) {
  return Object.assign(new Error(message), { publicMessage: message, status });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}

function html(content) {
  return new Response(content, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" } });
}

const HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#18273f"><title>AI Bot Manager</title>
<style>
:root{--navy:#18273f;--blue:#315f91;--pale:#eef3f8;--white:#fff;--line:#d7e0e9;--muted:#617087;--green:#22754b;--red:#a33d3d}*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:var(--navy);font-family:Inter,Arial,sans-serif}.shell{max-width:980px;margin:auto;padding:24px 18px 48px}.header{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}.brand h1{font-size:27px;margin:0}.brand p{color:var(--muted);margin:5px 0 0}.version{font-size:12px;color:var(--muted)}.card{background:var(--white);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 10px 30px #18273f0d;margin-bottom:18px}.login{max-width:500px;margin:10vh auto}.field{margin-bottom:15px}label{display:block;font-weight:700;font-size:13px;margin-bottom:7px}input,textarea,select{width:100%;border:1px solid var(--line);border-radius:11px;padding:13px;font:inherit;color:var(--navy);background:white}input{font-size:18px}textarea{min-height:155px;resize:vertical}.button{border:0;border-radius:999px;background:var(--blue);color:white;padding:12px 19px;font-weight:700;cursor:pointer}.button.secondary{background:white;color:var(--blue);border:1px solid var(--blue)}.button:disabled{opacity:.55;cursor:wait}.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px}.botGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}.bot{border:1px solid var(--line);border-radius:15px;padding:17px;cursor:pointer;background:white;text-align:left;color:inherit}.bot:hover,.bot.selected{border-color:var(--blue);box-shadow:0 0 0 2px #315f9120}.bot h3{margin:0 0 7px;font-size:17px}.bot p{color:var(--muted);font-size:13px;line-height:1.45;min-height:38px}.links{display:flex;gap:12px;font-size:13px}.links a{color:var(--blue)}.status{font-size:13px;min-height:20px;margin-top:12px}.error{color:var(--red)}.success{color:var(--green)}.requestPanel{display:none}.requestPanel.active{display:block}.requestHeader{display:flex;justify-content:space-between;align-items:start;gap:10px}.badge{font-size:12px;background:var(--pale);border-radius:999px;padding:6px 10px;color:var(--blue)}.help{color:var(--muted);font-size:13px;line-height:1.5}.result{display:none;margin-top:16px;padding:14px;background:#f0f8f4;border:1px solid #b9ddca;border-radius:12px}.result a{color:var(--green);font-weight:700}.fileHelp{margin-top:7px}.previewGrid{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}.previewGrid img{width:105px;height:75px;object-fit:cover;border:1px solid var(--line);border-radius:9px}.hidden{display:none!important}@media(max-width:600px){.shell{padding:16px 10px}.header,.topbar,.requestHeader{align-items:flex-start;flex-direction:column}.card{padding:17px}.button{width:100%}}
</style></head><body><main class="shell">
<header class="header"><div class="brand"><h1>AI Bot Manager</h1><p>Request and track controlled changes to authorised chatbots.</p></div><div class="version">Version ${APP_VERSION}</div></header>
<section id="loginCard" class="card login"><h2>Sign in</h2><p class="help">Enter your name and six-digit administrator PIN. Your PIN determines which chatbots you can access.</p><form id="loginForm"><div class="field"><label for="name">Your name</label><input id="name" maxlength="60" autocomplete="name" required></div><div class="field"><label for="pin">Six-digit PIN</label><input id="pin" type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="current-password" required></div><button class="button" type="submit">Sign in</button><div id="loginStatus" class="status" role="status"></div></form></section>
<section id="app" class="hidden"><div class="card topbar"><div><strong id="welcome"></strong><div id="role" class="help"></div></div><button id="logout" class="button secondary" type="button">Sign out</button></div>
<section class="card"><h2>Your chatbots</h2><p class="help">Select a chatbot to request a change. You will only see chatbots permitted for your role.</p><div id="bots" class="botGrid"></div></section>
<section id="requestPanel" class="card requestPanel"><div class="requestHeader"><div><h2 id="requestTitle">Request a change</h2></div><span class="badge">Tracked change request</span></div><form id="requestForm"><div class="field"><label for="requestText">What would you like changed?</label><textarea id="requestText" maxlength="6000" placeholder="Describe what should change, why it is needed, and an example of the expected result." required></textarea></div><div class="field"><label for="screenshots">Screenshots, optional</label><input id="screenshots" type="file" accept="image/png,image/jpeg,image/webp,image/gif" multiple><div class="help fileHelp">Up to five images, maximum 5 MB each.</div><div id="screenshotPreviews" class="previewGrid"></div></div><button id="submitRequest" class="button" type="submit">Submit change request</button><div id="requestStatus" class="status" role="status"></div><div id="requestResult" class="result"></div></form></section>
</section></main><script>
let selectedBot=null;const $=id=>document.getElementById(id);
async function api(path,options={}){const response=await fetch(path,{cache:'no-store',credentials:'same-origin',...options});const body=await response.text();let data;try{data=JSON.parse(body)}catch{const e=new Error('The server returned an unexpected response (HTTP '+response.status+'). Check the Cloudflare logs.');e.status=response.status;throw e}if(!response.ok){const e=new Error(data.error||'Unable to complete the request.');e.status=response.status;throw e}return data}
function status(el,message,error=false){el.textContent=message;el.className='status '+(error?'error':'')}
async function initialise(){try{const session=await api('/api/session');if(session.authenticated)await showApp(session);else showLogin()}catch{showLogin()}}
function showLogin(){$('loginCard').classList.remove('hidden');$('app').classList.add('hidden')}
async function showApp(session){$('loginCard').classList.add('hidden');$('app').classList.remove('hidden');$('welcome').textContent='Signed in as '+session.name;$('role').textContent=session.roleLabel;const data=await api('/api/bots');renderBots(data.bots)}
function renderBots(bots){const host=$('bots');host.replaceChildren();for(const bot of bots){const card=document.createElement('button');card.type='button';card.className='bot';card.innerHTML='<h3></h3><p></p><div class="links"><a target="_blank" rel="noopener">Live bot</a><a href="#requestPanel">Request a Change</a></div>';card.querySelector('h3').textContent=bot.name;card.querySelector('p').textContent=bot.description;const links=card.querySelectorAll('a');links[0].href=bot.liveUrl;links[0].addEventListener('click',event=>event.stopPropagation());links[1].addEventListener('click',event=>{event.preventDefault();event.stopPropagation();selectBot(bot,card);$('requestPanel').scrollIntoView({behavior:'smooth',block:'start'})});card.addEventListener('click',()=>selectBot(bot,card));host.appendChild(card)}}
function selectBot(bot,card){selectedBot=bot;document.querySelectorAll('.bot').forEach(x=>x.classList.remove('selected'));card.classList.add('selected');$('requestTitle').textContent='Request a change to '+bot.name;$('requestPanel').classList.add('active');$('requestResult').style.display='none';status($('requestStatus'),'');$('requestText').focus()}
$('loginForm').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;status($('loginStatus'),'Checking access...');try{const session=await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('name').value,pin:$('pin').value})});$('pin').value='';status($('loginStatus'),'');await showApp(session)}catch(error){status($('loginStatus'),error.message,true)}finally{button.disabled=false}});
$('logout').addEventListener('click',async()=>{await api('/api/logout',{method:'POST'});selectedBot=null;$('requestPanel').classList.remove('active');showLogin()});
$('requestForm').addEventListener('submit',async event=>{event.preventDefault();if(!selectedBot)return;const button=$('submitRequest');button.disabled=true;status($('requestStatus'),'Submitting change request...');$('requestResult').style.display='none';try{const formData=new FormData();formData.append('botId',selectedBot.id);formData.append('request',$('requestText').value);for(const file of $('screenshots').files)formData.append('screenshots',file);const data=await api('/api/change-requests',{method:'POST',body:formData});status($('requestStatus'),'Request created.','');$('requestResult').textContent='Request #'+data.issueNumber+' has been created with '+data.screenshotCount+' screenshot'+(data.screenshotCount===1?'':'s')+' and has been submitted. You will review the proposed change before approving deployment.';$('requestResult').style.display='block';$('requestText').value='';$('screenshots').value='';$('screenshotPreviews').replaceChildren()}catch(error){status($('requestStatus'),error.message,true);if(error.status===401)showLogin()}finally{button.disabled=false}});
$('screenshots').addEventListener('change',()=>{const host=$('screenshotPreviews');host.replaceChildren();const files=[...$('screenshots').files];if(files.length>5){status($('requestStatus'),'You can attach up to five screenshots.',true);$('screenshots').value='';return}for(const file of files){const img=document.createElement('img');img.alt=file.name;img.src=URL.createObjectURL(file);img.onload=()=>URL.revokeObjectURL(img.src);host.appendChild(img)}});
initialise();
</script></body></html>`;
