const APP_VERSION = "2026.10.01.13";
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
      if (request.method === "GET" && url.pathname === "/api/change-list") { const session = await requireSession(request, env); return listChangeRequests(session, env); }
      if (request.method === "POST" && url.pathname === "/api/requests/prepare") return prepareChange(request, env);
      if (request.method === "POST" && url.pathname === "/api/requests/revise") return reviseChange(request, env);
      if (request.method === "POST" && url.pathname === "/api/requests/deploy") return deployChange(request, env);
      if (request.method === "POST" && url.pathname === "/api/requests/rollback") return prepareRollback(request, env);
      if (request.method === "POST" && url.pathname === "/api/requests/delete") return deleteChange(request, env);
      const shotMatch = url.pathname.match(/^\/api\/requests\/([^/]+)\/(\d+)\/screenshots\/(\d+)$/);
      if (request.method === "GET" && shotMatch) return getRequestScreenshot(request, env, shotMatch[1], Number(shotMatch[2]), Number(shotMatch[3]));
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
  if (!/^\d{6}$/.test(pin)) throw publicError("Enter a six-digit PIN.", 400);

  const identity = await identifyUser(pin, env);
  if (!identity) {
    attempts.set(ip, { count: (prior?.count || 0) + 1, until: prior?.until || now + 15 * 60 * 1000 });
    throw publicError("Incorrect PIN.", 401);
  }
  attempts.delete(ip);
  const issued = Math.floor(now / 1000);
  const payload = { role: identity.role, name: identity.name, iat: issued, exp: issued + SESSION_SECONDS, nonce: crypto.randomUUID() };
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

const SAFE_TEXT_EXTENSIONS = new Set(["js","mjs","cjs","ts","tsx","jsx","json","toml","html","css","md"]);
const MAX_AI_FILES = 3;
const MAX_CONTEXT_CHARS = 180000;

async function githubApi(env, repository, path, options = {}) {
  if (!env.GITHUB_TOKEN) throw publicError("GitHub is not connected.", 503);
  const response = await fetch("https://api.github.com/repos/" + repository + path, {
    ...options,
    headers: { "Accept":"application/vnd.github+json", "Authorization":"Bearer " + env.GITHUB_TOKEN, "Content-Type":"application/json", "User-Agent":"ai-bot-manager", "X-GitHub-Api-Version":"2022-11-28", ...(options.headers || {}) }
  });
  const raw = await response.text(); let data = null;
  try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
  if (!response.ok) {
    console.error("GitHub API error", response.status, path, typeof data === "string" ? data.slice(0,300) : data);
    throw publicError(response.status === 401 ? "The GitHub token is invalid or expired." : response.status === 403 ? "GitHub permission was denied." : response.status === 404 ? "The GitHub record or repository could not be found." : "GitHub could not complete this action.", 502);
  }
  return data;
}

function botForSession(botId, session) {
  const bot = BOTS.find(item => item.id === String(botId || ""));
  if (!bot || !allowedBots(session.role).some(item => item.id === bot.id)) throw publicError("You do not have access to that chatbot.", 403);
  return bot;
}

function ownsIssue(issue, session) { return String(issue.body || "").includes("- Requested by: " + session.name); }

function parseRequestMeta(body) {
  const text = String(body || "");
  const storage = text.match(/<!-- bot-manager-request-id:([^;]+);r2-keys:([^ ]*) -->/);
  const workflow = text.match(/<!-- bot-manager-workflow:([^>]+) -->/);
  const values = {};
  if (workflow) for (const part of workflow[1].split(";")) { const at = part.indexOf(":"); if (at > 0) values[part.slice(0,at)] = part.slice(at+1); }
  return { keys: storage && storage[2] ? storage[2].split("|").filter(Boolean) : [], pr:Number(values.pr || 0), branch:values.branch || "", stage:values.stage || "requested", mergedSha:values.merged || "", rollbackPr:Number(values.rollbackPr || 0), rollbackBranch:values.rollbackBranch || "" };
}

function replaceWorkflowMeta(body, values) {
  const marker = "<!-- bot-manager-workflow:" + Object.entries(values).filter(([,v]) => v !== "" && v !== 0 && v != null).map(([k,v]) => k + ":" + String(v).replace(/[;>]/g,"")).join(";") + " -->";
  return String(body || "").replace(/\n?<!-- bot-manager-workflow:[^>]+ -->/g, "").trimEnd() + "\n\n" + marker;
}

async function getOwnedIssue(request, env, body) {
  const session = await requireSession(request, env); const bot = botForSession(body.botId, session); const number = Number(body.issueNumber);
  if (!Number.isInteger(number) || number < 1) throw publicError("Invalid request number.", 400);
  const issue = await githubApi(env, bot.repository, "/issues/" + number);
  if (issue.pull_request || !ownsIssue(issue, session)) throw publicError("You can only review and deploy requests that you submitted.", 403);
  return { session, bot, issue, number, meta:parseRequestMeta(issue.body) };
}

async function listChangeRequests(session, env) {
  const output = [];
  for (const bot of allowedBots(session.role)) {
    const issues = await githubApi(env, bot.repository, "/issues?state=all&per_page=50&sort=updated&direction=desc");
    for (const issue of issues) {
      if (issue.pull_request || !ownsIssue(issue, session) || !String(issue.body || "").includes("Submitted through: AI Bot Manager")) continue;
      const meta = parseRequestMeta(issue.body); let pr = null; const prNumber = meta.rollbackPr || meta.pr;
      if (prNumber) try { const item = await githubApi(env, bot.repository, "/pulls/" + prNumber); const files = await githubApi(env, bot.repository, "/pulls/" + prNumber + "/files?per_page=20"); pr = { number:item.number, state:item.state, merged:item.merged, htmlUrl:item.html_url, files:files.map(file => ({ path:file.filename, additions:file.additions, deletions:file.deletions, patch:file.patch || "Diff is too large to display." })) }; } catch (error) { console.error("Unable to load PR", prNumber, error); }
      output.push({ botId:bot.id, botName:bot.name, issueNumber:issue.number, title:issue.title, request:String(issue.body || "").split("## Request details")[0].replace("## Requested change","").trim(), createdAt:issue.created_at, updatedAt:issue.updated_at, issueState:issue.state, screenshotCount:meta.keys.length, stage:meta.stage, pr, mergedSha:meta.mergedSha });
    }
  }
  output.sort((a,b) => new Date(b.updatedAt) - new Date(a.updatedAt)); return json({ requests:output });
}

async function getRequestScreenshot(request, env, botId, issueNumber, index) {
  const owned = await getOwnedIssue(request, env, { botId, issueNumber });
  if (!env.REQUEST_FILES || !owned.meta.keys[index]) throw publicError("Screenshot not found.", 404);
  const object = await env.REQUEST_FILES.get(owned.meta.keys[index]); if (!object) throw publicError("Screenshot not found.", 404);
  const headers = new Headers({ "Cache-Control":"private, no-store", "X-Content-Type-Options":"nosniff", "Content-Disposition":"inline" }); object.writeHttpMetadata(headers); return new Response(object.body, { headers });
}

function validSourcePath(path) { const clean=String(path||""); const ext=clean.includes(".") ? clean.split(".").pop().toLowerCase() : ""; return clean && !clean.startsWith(".github/workflows/") && !clean.includes("..") && SAFE_TEXT_EXTENSIONS.has(ext); }
function decodeGithubContent(value) { const binary=atob(String(value||"").replace(/\n/g,"")); return new TextDecoder().decode(Uint8Array.from(binary,c=>c.charCodeAt(0))); }
function encodeGithubContent(value) { const bytes=new TextEncoder().encode(value); let binary=""; for(let i=0;i<bytes.length;i+=32768) binary+=String.fromCharCode(...bytes.subarray(i,i+32768)); return btoa(binary); }

async function repositoryContext(env, bot) {
  const repo=await githubApi(env,bot.repository,""); const branch=repo.default_branch; const ref=await githubApi(env,bot.repository,"/git/ref/heads/"+encodeURIComponent(branch)); const tree=await githubApi(env,bot.repository,"/git/trees/"+ref.object.sha+"?recursive=1");
  const candidates=(tree.tree||[]).filter(item=>item.type==="blob"&&item.size<=80000&&validSourcePath(item.path)); let used=0; const files=[];
  for(const item of candidates){ if(used>=MAX_CONTEXT_CHARS)break; const data=await githubApi(env,bot.repository,"/contents/"+item.path+"?ref="+encodeURIComponent(branch)); const content=decodeGithubContent(data.content); if(used+content.length>MAX_CONTEXT_CHARS)continue; files.push({path:item.path,sha:data.sha,content}); used+=content.length; }
  return {branch,headSha:ref.object.sha,files};
}
function aiText(result){return String(result?.response||result?.result?.response||result?.choices?.[0]?.message?.content||"");}
function parseAiJson(text){const cleaned=String(text||"").trim().replace(/^```(?:json)?\s*/i,"").replace(/\s*```$/,"");const start=cleaned.indexOf("{"),end=cleaned.lastIndexOf("}");if(start<0||end<=start)throw publicError("The AI did not return a usable proposed change. Please add more detail and try again.",502);try{return JSON.parse(cleaned.slice(start,end+1));}catch{throw publicError("The AI proposal could not be read. Please try preparing it again.",502);}}

async function createProposal(env,bot,issue,extraInstructions=""){
  if(!env.AI)throw publicError("Cloudflare Workers AI is not connected.",503);const repo=await repositoryContext(env,bot);if(!repo.files.length)throw publicError("No suitable source files were found in this repository.",422);
  const sources=repo.files.map(file=>"\n--- FILE: "+file.path+" ---\n"+file.content).join("");
  const prompt=["You are preparing a small, safe code change for a Cloudflare Worker web application.","Return ONLY strict JSON with this shape: {\"summary\":\"short summary\",\"files\":[{\"path\":\"existing/path\",\"content\":\"complete replacement file content\"}]}","Rules: modify only existing files shown below; return no more than 3 files; never modify .github/workflows; never delete or rename files; each content value must be the complete replacement file; make the smallest change that satisfies the request; preserve existing behaviour and secrets; do not invent credentials.","Requested change:\n"+String(issue.body||"").split("## Request details")[0],extraInstructions?"Revision instructions:\n"+extraInstructions:"","Repository files:"+sources].filter(Boolean).join("\n\n");
  const result=await env.AI.run("@cf/google/gemma-4-26b-a4b-it",{messages:[{role:"system",content:"You are a careful senior software engineer. Output strict JSON only."},{role:"user",content:prompt}],max_tokens:16000,temperature:0.1});let proposal=null;try{proposal=parseAiJson(aiText(result));}catch(error){console.error("First AI proposal was not valid JSON",error.message);}if(!proposal||!Array.isArray(proposal.files)||!proposal.files.length||proposal.files.length>MAX_AI_FILES){const correction="Your previous response was invalid because it did not include between 1 and 3 complete changed files. You must implement the requested change now. Select the most relevant existing source file, make the smallest safe edit, and return only the required strict JSON. Do not explain or return an empty files array.";const retry=await env.AI.run("@cf/google/gemma-4-26b-a4b-it",{messages:[{role:"system",content:"You are a careful senior software engineer. Output strict JSON only and always provide 1 to 3 changed existing files."},{role:"user",content:prompt},{role:"assistant",content:aiText(result).slice(0,12000)},{role:"user",content:correction}],max_tokens:16000,temperature:0});proposal=parseAiJson(aiText(retry));}if(!Array.isArray(proposal.files)||!proposal.files.length||proposal.files.length>MAX_AI_FILES)throw publicError("The AI could not identify a safe code change. Add the screen, field or wording that should change and try again.",422);const known=new Map(repo.files.map(file=>[file.path,file]));
  const files=proposal.files.map(item=>{const path=String(item.path||"");const original=known.get(path);const content=String(item.content??"");if(!original||!validSourcePath(path))throw publicError("The AI attempted to change a file that is not permitted.",422);if(!content||content.length>250000)throw publicError("The AI returned an invalid file replacement.",422);return{path,content,sha:original.sha};});return{repo,summary:String(proposal.summary||"Proposed chatbot change").slice(0,180),files};
}

async function prepareChange(request,env){sameOrigin(request);const input=await request.json();const owned=await getOwnedIssue(request,env,input);if(owned.meta.pr&&owned.meta.stage==="review")throw publicError("This request already has a proposed change ready for review.",409);const proposal=await createProposal(env,owned.bot,owned.issue,String(input.revision||""));const branch="bot-manager/issue-"+owned.number+"-"+Date.now();await githubApi(env,owned.bot.repository,"/git/refs",{method:"POST",body:JSON.stringify({ref:"refs/heads/"+branch,sha:proposal.repo.headSha})});for(const file of proposal.files)await githubApi(env,owned.bot.repository,"/contents/"+file.path,{method:"PUT",body:JSON.stringify({message:"Prepare change for request #"+owned.number,content:encodeGithubContent(file.content),sha:file.sha,branch})});const pr=await githubApi(env,owned.bot.repository,"/pulls",{method:"POST",body:JSON.stringify({title:"AI proposal for request #"+owned.number,head:branch,base:proposal.repo.branch,body:"Prepared through AI Bot Manager for issue #"+owned.number+".\n\nThis pull request must be approved by "+owned.session.name+" before deployment."})});await githubApi(env,owned.bot.repository,"/issues/"+owned.number,{method:"PATCH",body:JSON.stringify({body:replaceWorkflowMeta(owned.issue.body,{pr:pr.number,branch,stage:"review"})})});return json({ok:true,prNumber:pr.number,summary:proposal.summary});}

async function reviseChange(request,env){sameOrigin(request);const input=await request.json();const owned=await getOwnedIssue(request,env,input);const revision=String(input.revision||"").trim();if(revision.length<5||revision.length>3000)throw publicError("Please describe the revision required.",400);const prNumber=owned.meta.stage==="rollback-review"?owned.meta.rollbackPr:owned.meta.pr;if(!prNumber||!["review","rollback-review"].includes(owned.meta.stage))throw publicError("There is no proposed change to revise.",409);await githubApi(env,owned.bot.repository,"/pulls/"+prNumber,{method:"PATCH",body:JSON.stringify({state:"closed"})});const body=String(owned.issue.body||"").replace(/\n?<!-- bot-manager-workflow:[^>]+ -->/g,"").trimEnd()+"\n\n## Revision requested\n"+revision;await githubApi(env,owned.bot.repository,"/issues/"+owned.number,{method:"PATCH",body:JSON.stringify({body:replaceWorkflowMeta(body,{stage:owned.meta.stage==="rollback-review"?"deployed":"revision",pr:owned.meta.pr,branch:owned.meta.branch,merged:owned.meta.mergedSha}),state:owned.meta.stage==="rollback-review"?"closed":"open"})});return json({ok:true});}

async function deployChange(request,env){sameOrigin(request);const input=await request.json();const owned=await getOwnedIssue(request,env,input);const isRollback=owned.meta.stage==="rollback-review";const prNumber=isRollback?owned.meta.rollbackPr:owned.meta.pr;const expectedBranch=isRollback?owned.meta.rollbackBranch:owned.meta.branch;if(!prNumber||!["review","rollback-review"].includes(owned.meta.stage))throw publicError("There is no prepared change ready to deploy.",409);const pr=await githubApi(env,owned.bot.repository,"/pulls/"+prNumber);if(pr.state!=="open"||pr.head?.ref!==expectedBranch)throw publicError("The prepared GitHub change is no longer open or does not match this request.",409);const merged=await githubApi(env,owned.bot.repository,"/pulls/"+prNumber+"/merge",{method:"PUT",body:JSON.stringify({merge_method:"squash",commit_title:(isRollback?"Rollback":"Deploy")+" request #"+owned.number})});if(!merged.merged)throw publicError("GitHub could not merge the proposed change.",409);await githubApi(env,owned.bot.repository,"/issues/"+owned.number,{method:"PATCH",body:JSON.stringify({body:replaceWorkflowMeta(owned.issue.body,{pr:owned.meta.pr,branch:owned.meta.branch,stage:isRollback?"rolled-back":"deployed",merged:merged.sha}),state:"closed"})});return json({ok:true,mergedSha:merged.sha,rollback:isRollback,message:isRollback?"Rollback merged. Cloudflare deployment should now start automatically.":"Change merged. Cloudflare deployment should now start automatically."});}

async function deleteChange(request,env){sameOrigin(request);const input=await request.json();const owned=await getOwnedIssue(request,env,input);if(["deployed","rolled-back"].includes(owned.meta.stage))throw publicError("A deployed change cannot be deleted. Use rollback instead.",409);const prNumber=owned.meta.stage==="rollback-review"?owned.meta.rollbackPr:owned.meta.pr;if(prNumber){const pr=await githubApi(env,owned.bot.repository,"/pulls/"+prNumber);if(pr.state==="open")await githubApi(env,owned.bot.repository,"/pulls/"+prNumber,{method:"PATCH",body:JSON.stringify({state:"closed"})});}await githubApi(env,owned.bot.repository,"/issues/"+owned.number,{method:"PATCH",body:JSON.stringify({body:replaceWorkflowMeta(owned.issue.body,{stage:"cancelled"}),state:"closed"})});return json({ok:true,message:"The proposed change was deleted. The live chatbot was not changed."});}

async function prepareRollback(request,env){sameOrigin(request);const input=await request.json();const owned=await getOwnedIssue(request,env,input);if(owned.meta.stage!=="deployed"||!owned.meta.pr||!owned.meta.mergedSha)throw publicError("Only a deployed change can be rolled back.",409);const changed=await githubApi(env,owned.bot.repository,"/pulls/"+owned.meta.pr+"/files?per_page=20");if(!changed.length||changed.length>MAX_AI_FILES||changed.some(file=>file.status!=="modified"||!validSourcePath(file.filename)))throw publicError("This change cannot be automatically rolled back safely.",422);const mergeCommit=await githubApi(env,owned.bot.repository,"/commits/"+owned.meta.mergedSha);const previousSha=mergeCommit.parents?.[0]?.sha;if(!previousSha)throw publicError("The previous version could not be identified.",422);const repo=await githubApi(env,owned.bot.repository,"");const defaultRef=await githubApi(env,owned.bot.repository,"/git/ref/heads/"+encodeURIComponent(repo.default_branch));const branch="bot-manager/rollback-"+owned.number+"-"+Date.now();await githubApi(env,owned.bot.repository,"/git/refs",{method:"POST",body:JSON.stringify({ref:"refs/heads/"+branch,sha:defaultRef.object.sha})});for(const file of changed){const oldFile=await githubApi(env,owned.bot.repository,"/contents/"+file.filename+"?ref="+previousSha);const currentFile=await githubApi(env,owned.bot.repository,"/contents/"+file.filename+"?ref="+encodeURIComponent(branch));await githubApi(env,owned.bot.repository,"/contents/"+file.filename,{method:"PUT",body:JSON.stringify({message:"Prepare rollback for request #"+owned.number,content:String(oldFile.content||"").replace(/\n/g,""),sha:currentFile.sha,branch})});}const pr=await githubApi(env,owned.bot.repository,"/pulls",{method:"POST",body:JSON.stringify({title:"Rollback request #"+owned.number,head:branch,base:repo.default_branch,body:"Restores the files changed by request #"+owned.number+" to their previous versions. Requires explicit approval by "+owned.session.name+"."})});await githubApi(env,owned.bot.repository,"/issues/"+owned.number,{method:"PATCH",body:JSON.stringify({body:replaceWorkflowMeta(owned.issue.body,{pr:owned.meta.pr,branch:owned.meta.branch,stage:"rollback-review",merged:owned.meta.mergedSha,rollbackPr:pr.number,rollbackBranch:branch}),state:"open"})});return json({ok:true,prNumber:pr.number});}

function allowedBots(role) {
  const groups = ROLES[role]?.groups || [];
  return BOTS.filter(bot => groups.includes(bot.group));
}

function publicSession(session) {
  return { authenticated: true, role: session.role, roleLabel: ROLES[session.role].label, name: session.name, expiresAt: new Date(session.exp * 1000).toISOString() };
}

async function identifyUser(pin, env) {
  const configured = [
    [{ role: "super_admin", name: "Ian Greig" }, env.SUPER_ADMIN_PIN],
    [{ role: "run_haven_admin", name: "Walter Pahor" }, env.RUN_HAVEN_ADMIN_PIN],
    [{ role: "confidence_admin", name: "Confidence Team" }, env.CONFIDENCE_ADMIN_PIN]
  ];
  for (const [identity, expected] of configured) {
    if (typeof expected === "string" && /^\d{6}$/.test(expected) && await safeEqual(pin, expected)) return identity;
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
  return new Response(content, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" } });
}

const HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#18273f"><title>AI Bot Manager</title>
<style>
:root{--navy:#18273f;--blue:#315f91;--pale:#eef3f8;--white:#fff;--line:#d7e0e9;--muted:#617087;--green:#22754b;--red:#a33d3d}*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:var(--navy);font-family:Inter,Arial,sans-serif}.shell{max-width:980px;margin:auto;padding:24px 18px 48px}.header{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}.brand h1{font-size:27px;margin:0}.brand p{color:var(--muted);margin:5px 0 0}.version{font-size:12px;color:var(--muted)}.card{background:var(--white);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 10px 30px #18273f0d;margin-bottom:18px}.login{max-width:500px;margin:10vh auto}.field{margin-bottom:15px}label{display:block;font-weight:700;font-size:13px;margin-bottom:7px}input,textarea,select{width:100%;border:1px solid var(--line);border-radius:11px;padding:13px;font:inherit;color:var(--navy);background:white}input{font-size:18px}textarea{min-height:155px;resize:vertical}.button{border:0;border-radius:999px;background:var(--blue);color:white;padding:12px 19px;font-weight:700;cursor:pointer}.button.secondary{background:white;color:var(--blue);border:1px solid var(--blue)}.button:disabled{opacity:.55;cursor:wait}.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px}.botGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}.bot{border:1px solid var(--line);border-radius:15px;padding:17px;cursor:pointer;background:white;text-align:left;color:inherit}.bot:hover,.bot.selected{border-color:var(--blue);box-shadow:0 0 0 2px #315f9120}.bot h3{margin:0 0 7px;font-size:17px}.bot p{color:var(--muted);font-size:13px;line-height:1.45;min-height:38px}.links{display:flex;gap:12px;font-size:13px}.links a{color:var(--blue)}.status{font-size:13px;min-height:20px;margin-top:12px}.error{color:var(--red)}.success{color:var(--green)}.requestPanel{display:none}.requestPanel.active{display:block}.requestHeader{display:flex;justify-content:space-between;align-items:start;gap:10px}.badge{font-size:12px;background:var(--pale);border-radius:999px;padding:6px 10px;color:var(--blue)}.help{color:var(--muted);font-size:13px;line-height:1.5}.result{display:none;margin-top:16px;padding:14px;background:#f0f8f4;border:1px solid #b9ddca;border-radius:12px}.result a{color:var(--green);font-weight:700}.fileHelp{margin-top:7px}.previewGrid{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}.previewGrid img{width:105px;height:75px;object-fit:cover;border:1px solid var(--line);border-radius:9px}.requestList{display:grid;gap:14px}.requestItem{border:1px solid var(--line);border-radius:14px;padding:16px}.requestItem h3{margin:0 0 6px}.requestMeta{font-size:12px;color:var(--muted);margin-bottom:10px}.requestText{white-space:pre-wrap;background:var(--pale);padding:11px;border-radius:9px;font-size:13px}.requestActions{display:flex;flex-wrap:wrap;gap:9px;margin-top:12px}.requestActions .button{padding:9px 14px}.diff{margin-top:12px}.diff details{border:1px solid var(--line);border-radius:9px;margin:7px 0}.diff summary{cursor:pointer;padding:10px;font-weight:700}.diff pre{overflow:auto;max-height:360px;margin:0;padding:12px;background:#111827;color:#e5e7eb;font-size:11px}.requestShots{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.requestShots img{width:110px;height:78px;object-fit:cover;border-radius:8px;border:1px solid var(--line)}.warning{background:#fff7e6;border:1px solid #edcf8d;padding:11px;border-radius:10px;font-size:13px}.hidden{display:none!important}@media(max-width:600px){.shell{padding:16px 10px}.header,.topbar,.requestHeader{align-items:flex-start;flex-direction:column}.card{padding:17px}.button{width:100%}}
</style></head><body><main class="shell">
<header class="header"><div class="brand"><h1>AI Bot Manager</h1><p>Request and track controlled changes to authorised chatbots.</p></div><div class="version">Version ${APP_VERSION}</div></header>
<section id="loginCard" class="card login"><h2>Sign in</h2><p class="help">Enter your six-digit PIN. Your PIN identifies you and determines which chatbots you can access.</p><form id="loginForm"><div class="field"><label for="pin">Six-digit PIN</label><input id="pin" type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="current-password" required></div><button class="button" type="submit">Sign in</button><div id="loginStatus" class="status" role="status"></div></form></section>
<section id="app" class="hidden"><div class="card topbar"><div><strong id="welcome"></strong><div id="role" class="help"></div></div><button id="logout" class="button secondary" type="button">Sign out</button></div>
<section class="card"><h2>Your chatbots</h2><p class="help">Select a chatbot to request a change. You will only see chatbots permitted for your role.</p><div id="bots" class="botGrid"></div></section>
<section id="requestPanel" class="card requestPanel"><div class="requestHeader"><div><h2 id="requestTitle">Request a change</h2></div><span class="badge">Tracked change request</span></div><form id="requestForm"><div class="field"><label for="requestText">What would you like changed?</label><textarea id="requestText" maxlength="6000" placeholder="Describe what should change, why it is needed, and an example of the expected result." required></textarea></div><div class="field"><label for="screenshots">Screenshots, optional</label><input id="screenshots" type="file" accept="image/png,image/jpeg,image/webp,image/gif" multiple><div class="help fileHelp">Up to five images, maximum 5 MB each.</div><div id="screenshotPreviews" class="previewGrid"></div></div><button id="submitRequest" class="button" type="submit">Submit change request</button><div id="requestStatus" class="status" role="status"></div><div id="requestResult" class="result"></div></form></section>
<section id="myRequests" class="card"><div class="requestHeader"><div><h2>My Requests</h2><p class="help">Prepare changes, review every changed file, deploy, or restore the previous version.</p></div><button id="refreshRequests" class="button secondary" type="button">Refresh</button></div><div id="requestsStatus" class="status"></div><div id="requestList" class="requestList"></div></section>
</section></main><script>
let selectedBot=null;const $=id=>document.getElementById(id);
async function api(path,options={}){const response=await fetch(path,{cache:'no-store',credentials:'same-origin',...options});const body=await response.text();let data;try{data=JSON.parse(body)}catch{const e=new Error('The server returned an unexpected response (HTTP '+response.status+'). Check the Cloudflare logs.');e.status=response.status;throw e}if(!response.ok){const e=new Error(data.error||'Unable to complete the request.');e.status=response.status;throw e}return data}
function status(el,message,error=false){el.textContent=message;el.className='status '+(error?'error':'')}
async function initialise(){try{const session=await api('/api/session');if(session.authenticated)await showApp(session);else showLogin()}catch{showLogin()}}
function showLogin(){$('loginCard').classList.remove('hidden');$('app').classList.add('hidden')}
async function showApp(session){$('loginCard').classList.add('hidden');$('app').classList.remove('hidden');$('welcome').textContent='Signed in as '+session.name;$('role').textContent=session.roleLabel;const data=await api('/api/bots');renderBots(data.bots);await loadRequests()}
function renderBots(bots){const host=$('bots');host.replaceChildren();for(const bot of bots){const card=document.createElement('button');card.type='button';card.className='bot';card.innerHTML='<h3></h3><p></p><div class="links"><a target="_blank" rel="noopener">Live bot</a><a href="#requestPanel">Request a Change</a></div>';card.querySelector('h3').textContent=bot.name;card.querySelector('p').textContent=bot.description;const links=card.querySelectorAll('a');links[0].href=bot.liveUrl;links[0].addEventListener('click',event=>event.stopPropagation());links[1].addEventListener('click',event=>{event.preventDefault();event.stopPropagation();selectBot(bot,card);$('requestPanel').scrollIntoView({behavior:'smooth',block:'start'})});card.addEventListener('click',()=>selectBot(bot,card));host.appendChild(card)}}
function selectBot(bot,card){selectedBot=bot;document.querySelectorAll('.bot').forEach(x=>x.classList.remove('selected'));card.classList.add('selected');$('requestTitle').textContent='Request a change to '+bot.name;$('requestPanel').classList.add('active');$('requestResult').style.display='none';status($('requestStatus'),'');$('requestText').focus()}
$('loginForm').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;status($('loginStatus'),'Checking access...');try{const session=await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:$('pin').value})});$('pin').value='';status($('loginStatus'),'');await showApp(session)}catch(error){status($('loginStatus'),error.message,true)}finally{button.disabled=false}});
$('logout').addEventListener('click',async()=>{await api('/api/logout',{method:'POST'});selectedBot=null;$('requestPanel').classList.remove('active');showLogin()});
$('requestForm').addEventListener('submit',async event=>{event.preventDefault();if(!selectedBot)return;const button=$('submitRequest');button.disabled=true;status($('requestStatus'),'Submitting change request...');$('requestResult').style.display='none';try{const formData=new FormData();formData.append('botId',selectedBot.id);formData.append('request',$('requestText').value);for(const file of $('screenshots').files)formData.append('screenshots',file);const data=await api('/api/change-requests',{method:'POST',body:formData});status($('requestStatus'),'Request created.','');$('requestResult').textContent='Request #'+data.issueNumber+' has been created with '+data.screenshotCount+' screenshot'+(data.screenshotCount===1?'':'s')+' and has been submitted. You will review the proposed change before approving deployment.';$('requestResult').style.display='block';$('requestText').value='';$('screenshots').value='';$('screenshotPreviews').replaceChildren();await loadRequests()}catch(error){status($('requestStatus'),error.message,true);if(error.status===401)showLogin()}finally{button.disabled=false}});
async function loadRequests(){const host=$('requestList');status($('requestsStatus'),'Loading requests...');try{const data=await api('/api/change-list');host.replaceChildren();if(!data.requests.length){host.innerHTML='<p class="help">No change requests have been submitted yet.</p>';status($('requestsStatus'),'');return}for(const item of data.requests)host.appendChild(renderRequest(item));status($('requestsStatus'),'')}catch(error){status($('requestsStatus'),error.message,true)}}
function actionButton(label,fn,secondary=false){const button=document.createElement('button');button.type='button';button.className='button'+(secondary?' secondary':'');button.textContent=label;button.addEventListener('click',async()=>{button.disabled=true;try{await fn()}catch(error){alert(error.message)}finally{button.disabled=false}});return button}
function renderRequest(item){const card=document.createElement('article');card.className='requestItem';const title=document.createElement('h3');title.textContent='#'+item.issueNumber+' '+item.title.replace(/^Change request:\s*/,'');card.appendChild(title);const meta=document.createElement('div');meta.className='requestMeta';meta.textContent=item.botName+' • '+new Date(item.createdAt).toLocaleString()+' • '+item.stage.replaceAll('-',' ');card.appendChild(meta);const request=document.createElement('div');request.className='requestText';request.textContent=item.request;card.appendChild(request);if(item.screenshotCount){const shots=document.createElement('div');shots.className='requestShots';for(let i=0;i<item.screenshotCount;i++){const a=document.createElement('a');a.href='/api/requests/'+encodeURIComponent(item.botId)+'/'+item.issueNumber+'/screenshots/'+i;a.target='_blank';const img=document.createElement('img');img.src=a.href;img.alt='Screenshot '+(i+1);a.appendChild(img);shots.appendChild(a)}card.appendChild(shots)}if(item.pr&&item.pr.files){const diff=document.createElement('div');diff.className='diff';const heading=document.createElement('p');heading.innerHTML='<strong>Proposed files</strong> — review these before deployment.';diff.appendChild(heading);for(const file of item.pr.files){const details=document.createElement('details');const summary=document.createElement('summary');summary.textContent=file.path+' (+'+file.additions+' / -'+file.deletions+')';const pre=document.createElement('pre');pre.textContent=file.patch;details.append(summary,pre);diff.appendChild(details)}card.appendChild(diff)}const actions=document.createElement('div');actions.className='requestActions';if(['requested','revision'].includes(item.stage))actions.appendChild(actionButton(item.stage==='revision'?'Prepare revised change':'Prepare proposed change',async()=>{if(!confirm('Ask AI to prepare a code change for review? No deployment will happen yet.'))return;await api('/api/requests/prepare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botId:item.botId,issueNumber:item.issueNumber})});await loadRequests()}));if(['requested','revision'].includes(item.stage))actions.appendChild(actionButton('Delete request',async()=>{if(!confirm('Delete this change request?'))return;const result=await api('/api/requests/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botId:item.botId,issueNumber:item.issueNumber})});alert(result.message);await loadRequests()},true));if(item.stage==='review'){actions.appendChild(actionButton('Approve and deploy',async()=>{if(!confirm('Deploy this exact proposed change? Cloudflare will start deployment after GitHub merges it.'))return;const result=await api('/api/requests/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botId:item.botId,issueNumber:item.issueNumber})});alert(result.message);await loadRequests()}));actions.appendChild(actionButton('Request revision',async()=>{const revision=prompt('What should be changed in the proposal?');if(!revision)return;await api('/api/requests/revise',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botId:item.botId,issueNumber:item.issueNumber,revision})});await loadRequests()},true));actions.appendChild(actionButton('Delete proposed change',async()=>{if(!confirm('Delete this proposed change? The live chatbot will not be changed.'))return;const result=await api('/api/requests/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botId:item.botId,issueNumber:item.issueNumber})});alert(result.message);await loadRequests()},true))}if(item.stage==='deployed')actions.appendChild(actionButton('Prepare rollback',async()=>{if(!confirm('Prepare a rollback to the files from immediately before this deployment? You will review it before it is deployed.'))return;await api('/api/requests/rollback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botId:item.botId,issueNumber:item.issueNumber})});await loadRequests()},true));if(item.stage==='rollback-review'){const warning=document.createElement('div');warning.className='warning';warning.textContent='Rollback prepared. Review the file differences above before restoring the previous version.';card.appendChild(warning);actions.appendChild(actionButton('Approve rollback and deploy',async()=>{if(!confirm('Restore the previous version now? This creates a new auditable deployment.'))return;const result=await api('/api/requests/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botId:item.botId,issueNumber:item.issueNumber})});alert(result.message);await loadRequests()}));actions.appendChild(actionButton('Keep current version',async()=>{const revision='Cancel the prepared rollback and keep the current deployed version.';await api('/api/requests/revise',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botId:item.botId,issueNumber:item.issueNumber,revision})});await loadRequests()},true))}card.appendChild(actions);return card}
$('refreshRequests').addEventListener('click',loadRequests);

$('screenshots').addEventListener('change',()=>{const host=$('screenshotPreviews');host.replaceChildren();const files=[...$('screenshots').files];if(files.length>5){status($('requestStatus'),'You can attach up to five screenshots.',true);$('screenshots').value='';return}for(const file of files){const img=document.createElement('img');img.alt=file.name;img.src=URL.createObjectURL(file);img.onload=()=>URL.revokeObjectURL(img.src);host.appendChild(img)}});
initialise();
</script></body></html>`;
