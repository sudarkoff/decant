var __defProp = Object.defineProperty;
var __export = (target2, all) => {
  for (var name in all)
    __defProp(target2, name, { get: all[name], enumerable: true });
};

// action/src/deps.ts
import * as nodeFs from "node:fs/promises";

// action/src/exec.ts
import { spawn } from "node:child_process";
var SECRET_NAME = /TOKEN|SECRET|KEY|PASSWORD/i;
function scrubEnv(env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    if (v === void 0) continue;
    if (k.startsWith("INPUT_") || k.startsWith("ACTIONS_") || SECRET_NAME.test(k)) continue;
    out[k] = v;
  }
  return out;
}
var defaultExec = (cmd, args, opts = {}) => new Promise((resolve4) => {
  const child = spawn(cmd, args, {
    cwd: opts.cwd,
    env: { ...scrubEnv(process.env), ...opts.env },
    shell: false,
    stdio: ["pipe", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (d) => stdout += d);
  child.stderr.setEncoding("utf8").on("data", (d) => stderr += d);
  child.on("error", (e) => resolve4({ code: 127, stdout, stderr: stderr + String(e.message) }));
  child.on("close", (code) => resolve4({ code: code ?? 1, stdout, stderr }));
  child.stdin.on("error", () => {
  });
  child.stdin.end(opts.input ?? "");
});

// action/src/http.ts
var TIMEOUT_MS = 3e4;
var OSV_TIMEOUT_MS = 1e4;
function redact(s, secrets) {
  let out = s;
  for (const sec of secrets) {
    if (!sec) continue;
    out = out.split(sec).join("***");
  }
  return out;
}
async function request(f, url, init, o) {
  try {
    return await f(url, { ...init, signal: AbortSignal.timeout(o.timeoutMs) });
  } catch (e) {
    throw new Error(redact(`${o.label}: ${failure(e, o.timeoutMs)}`, o.secrets ?? []));
  }
}
var isTimeout = (e) => ["TimeoutError", "AbortError"].includes(e?.name);
function failure(e, timeoutMs) {
  if (isTimeout(e)) return `timed out after ${timeoutMs / 1e3}s`;
  const msg = String(e?.message ?? e);
  const cause = e?.cause;
  const code = typeof cause?.code === "string" ? cause.code : "";
  const cmsg = typeof cause?.message === "string" ? cause.message : "";
  const why = code && cmsg && !cmsg.includes(code) ? `${code}: ${cmsg}` : code || cmsg;
  return why && !msg.includes(why) ? `${msg} (${why})` : msg;
}
var RETRY_DELAYS_MS = [500, 1e3, 2e3];
var RETRY_DEADLINE_MS = 6e4;
var RETRY_STATUSES = /* @__PURE__ */ new Set([502, 503, 504]);
var realSleep = (ms) => new Promise((resolve4) => setTimeout(resolve4, ms));
async function requestWithRetry(f, url, init, o) {
  const attempts = RETRY_DELAYS_MS.length + 1;
  const random = o.random ?? Math.random;
  const now = o.now ?? Date.now;
  const deadlineMs = o.deadlineMs ?? RETRY_DEADLINE_MS;
  const end = now() + deadlineMs;
  const retryStatuses = o.retryStatuses ?? true;
  for (let i = 0; ; i++) {
    const delay = i < RETRY_DELAYS_MS.length ? Math.round(RETRY_DELAYS_MS[i] * (0.75 + 0.5 * random())) : 0;
    const last = i === attempts - 1;
    const timeoutMs = Math.max(1, Math.min(o.timeoutMs, end - now()));
    let res;
    try {
      res = await f(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) {
      if (last || now() + delay >= end) {
        const why = isTimeout(e) ? `timed out (${Math.round(timeoutMs / 1e3)}s)` : failure(e, timeoutMs);
        const n = `${i + 1} attempt${i === 0 ? "" : "s"}`;
        const cut = i < attempts - 1 ? ` (${deadlineMs / 1e3}s deadline)` : "";
        throw new Error(redact(`${o.label}: ${why} after ${n}${cut}`, o.secrets ?? []));
      }
      await o.sleep(delay);
      continue;
    }
    if (last || !retryStatuses || !RETRY_STATUSES.has(res.status) || now() + delay >= end) return res;
    await res.body?.cancel().catch(() => {
    });
    await o.sleep(delay);
  }
}
async function httpError(res, o) {
  let text = "";
  try {
    text = (await res.text()).slice(0, 300).replace(/\s+/g, " ").trim();
  } catch {
  }
  return new Error(redact(`${o.label}: HTTP ${res.status}${text ? ` ${text}` : ""}`, o.secrets ?? []));
}
async function readJson(res, label) {
  try {
    return await res.json();
  } catch {
    throw new Error(`${label}: invalid JSON response`);
  }
}

// action/src/deps.ts
var defaultFs = {
  readFile: (p) => nodeFs.readFile(p, "utf8"),
  writeFile: (p, data, mode) => nodeFs.writeFile(p, data, mode === void 0 ? void 0 : { mode }),
  writeBytes: (p, data) => nodeFs.writeFile(p, data),
  async readdir(p) {
    const entries = await nodeFs.readdir(p, { withFileTypes: true });
    return Promise.all(
      entries.map(async (e) => {
        const isSymlink = e.isSymbolicLink();
        let isDir = e.isDirectory();
        if (isSymlink) isDir = await nodeFs.stat(`${p}/${e.name}`).then((s) => s.isDirectory(), () => false);
        return { name: e.name, isDir, isSymlink };
      })
    );
  },
  async exists(p) {
    try {
      await nodeFs.access(p);
      return true;
    } catch {
      return false;
    }
  },
  chmod: (p, mode) => nodeFs.chmod(p, mode),
  rm: (p) => nodeFs.rm(p, { force: true, recursive: true }),
  mkdtemp: (prefix) => nodeFs.mkdtemp(prefix),
  async mkdir(p) {
    await nodeFs.mkdir(p, { recursive: true });
  }
};
function defaultDeps() {
  return {
    env: process.env,
    fetch: globalThis.fetch,
    exec: defaultExec,
    now: () => /* @__PURE__ */ new Date(),
    sleep: realSleep,
    fs: defaultFs
  };
}

// action/src/gh-io.ts
import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
function getInput(name, env = process.env) {
  const key2 = name.replace(/ /g, "_").toUpperCase();
  return (env[`INPUT_${key2}`] ?? env[`INPUT_${key2.replace(/-/g, "_")}`] ?? "").trim();
}
function escapeData(s) {
  return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeProp(s) {
  return escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
}
function command(level, msg, file) {
  const props = file ? ` file=${escapeProp(file)}` : "";
  process.stdout.write(`::${level}${props}::${escapeData(msg)}
`);
}
function mask(v) {
  if (v) command("add-mask", v);
}
var notice = (msg, file) => command("notice", msg, file);
var warning = (msg, file) => command("warning", msg, file);
var error = (msg, file) => command("error", msg, file);
function appendTo(envName, text, env) {
  const path = env[envName];
  if (path) appendFileSync(path, text);
}
function keyValue(k, v) {
  const delim = `ghadelim_${randomUUID()}`;
  return `${k}<<${delim}
${v}
${delim}
`;
}
function setOutput(k, v, env = process.env) {
  appendTo("GITHUB_OUTPUT", keyValue(k, v), env);
}
function appendSummary(md, env = process.env) {
  appendTo("GITHUB_STEP_SUMMARY", `${md}
`, env);
}
function exportVar(k, v, env = process.env) {
  appendTo("GITHUB_ENV", keyValue(k, v), env);
}

// action/src/inputs.ts
function readInputs(env) {
  const g = (n, d = "") => getInput(n, env) || d;
  return {
    mode: g("mode"),
    decantUrl: g("decant-url"),
    token: g("token"),
    syncToken: g("sync-token"),
    githubToken: g("github-token"),
    policyPath: g("policy-path", "decant.json"),
    failOn: g("fail-on", "high"),
    workingDirectory: g("working-directory", "."),
    bypass: g("bypass", "false").toLowerCase() === "true",
    bypassReason: g("bypass-reason"),
    project: g("project")
  };
}

// action/src/modes/adopt.ts
var adopt_exports = {};
__export(adopt_exports, {
  defaultProject: () => defaultProject,
  run: () => run
});
import { isAbsolute, join, relative, resolve } from "node:path";

// src/ids.ts
function formatPackageId(p) {
  return `${p.eco}:${p.name}@${p.version}`;
}
function parsePackageId(id) {
  const colon = id.indexOf(":");
  if (colon < 0) return null;
  const eco = id.slice(0, colon);
  if (eco !== "npm" && eco !== "go" && eco !== "docker") return null;
  const rest = id.slice(colon + 1);
  const at = rest.lastIndexOf("@");
  if (at <= 0 || at === rest.length - 1) return null;
  const name = rest.slice(0, at);
  const version = rest.slice(at + 1);
  if (eco === "docker" && !(isImageRepo(name) && DIGEST_RE.test(version))) return null;
  return { eco, name, version };
}
var DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
var DOCKER_HUB_ALIASES = /* @__PURE__ */ new Set(["index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"]);
var HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]{1,5})?$/;
var PATH_RE = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
function isImageRepo(s) {
  if (s.length > 255) return false;
  const parts = s.split("/");
  if (parts.length < 2) return false;
  const host = parts[0];
  if (!HOST_RE.test(host) || !(host.includes(".") || host.includes(":") || host === "localhost")) return false;
  if (DOCKER_HUB_ALIASES.has(host)) return false;
  if (host === "docker.io" && parts.length !== 3) return false;
  return parts.slice(1).every((p) => PATH_RE.test(p));
}
var PROJECT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

// src/policy/schema.ts
var SEVERITIES = ["critical", "high", "moderate", "low"];
var DEFAULT_AUTOSHIP = {
  critical: "auto",
  high: "auto",
  moderate: "approve",
  low: "approve"
};
var ADVISORY_RE = /^(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,}|[A-Z]+-\d{4}-[A-Za-z0-9-]+)$/;
var TOP_KEYS = /* @__PURE__ */ new Set(["$schema", "project", "cooldownDays", "autoShip", "allow", "block"]);
function isObj(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isRealDate(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = /* @__PURE__ */ new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}
function entry(raw, path, withAdded, errors) {
  if (!isObj(raw)) {
    errors.push(`${path} must be an object`);
    return null;
  }
  const allowed = /* @__PURE__ */ new Set(["package", "reason", "advisory", ...withAdded ? ["added"] : []]);
  for (const k of Object.keys(raw)) if (!allowed.has(k)) errors.push(`${path}.${k} is not allowed`);
  const n = errors.length;
  const out = { package: "", reason: "" };
  if (typeof raw.package !== "string" || parsePackageId(raw.package) === null) errors.push(`${path}.package must be a package ID like npm:name@1.0.0 (images: docker:docker.io/library/node@sha256:<64 hex>)`);
  else out.package = raw.package;
  if (typeof raw.reason !== "string" || raw.reason === "") errors.push(`${path}.reason must be a non-empty string`);
  else out.reason = raw.reason;
  if (raw.advisory !== void 0) {
    if (typeof raw.advisory !== "string" || !ADVISORY_RE.test(raw.advisory)) errors.push(`${path}.advisory is not a valid advisory ID`);
    else out.advisory = raw.advisory;
  }
  if (withAdded) {
    if (typeof raw.added !== "string" || !isRealDate(raw.added)) errors.push(`${path}.added must be a real date in YYYY-MM-DD form`);
    else out.added = raw.added;
  }
  return errors.length === n ? out : null;
}
function parsePolicy(input) {
  if (!isObj(input)) return { ok: false, errors: ["policy must be a JSON object"] };
  const errors = [];
  for (const k of Object.keys(input)) if (!TOP_KEYS.has(k)) errors.push(`unknown key: ${k}`);
  let project = "";
  if (typeof input.project !== "string" || input.project === "") errors.push("project must be a non-empty string");
  else if (!PROJECT_ID_RE.test(input.project)) errors.push(`project must match ${PROJECT_ID_RE.source}`);
  else project = input.project;
  let cooldownDays = 7;
  if (input.cooldownDays !== void 0) {
    const c = input.cooldownDays;
    if (typeof c !== "number" || !Number.isInteger(c) || c < 0 || c > 365) errors.push("cooldownDays must be an integer from 0 to 365");
    else cooldownDays = c;
  }
  const autoShip = { ...DEFAULT_AUTOSHIP };
  if (input.autoShip !== void 0) {
    if (!isObj(input.autoShip)) errors.push("autoShip must be an object");
    else {
      for (const [k, v] of Object.entries(input.autoShip)) {
        if (!SEVERITIES.includes(k)) errors.push(`autoShip.${k} is not a known severity`);
        else if (v !== "auto" && v !== "approve") errors.push(`autoShip.${k} must be 'auto' or 'approve'`);
        else autoShip[k] = v;
      }
    }
  }
  const allow = [];
  const block = [];
  for (const [key2, withAdded] of [["allow", true], ["block", false]]) {
    const raw = input[key2];
    if (raw === void 0) continue;
    if (!Array.isArray(raw)) {
      errors.push(`${key2} must be an array`);
      continue;
    }
    raw.forEach((r, i) => {
      const e = entry(r, `${key2}[${i}]`, withAdded, errors);
      if (e) (withAdded ? allow : block).push(e);
    });
  }
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, policy: { project, cooldownDays, autoShip, allow, block } };
}

// action/src/checkout.ts
async function defaultHeadCheckout(gh, env, mode) {
  const base = await gh.defaultBranch();
  if (env.GITHUB_REF !== `refs/heads/${base}`) {
    return { ok: false, message: `decant ${mode} runs on the default branch (${base}), not ${env.GITHUB_REF || "(unknown ref)"}` };
  }
  const sha = env.GITHUB_SHA ?? "";
  if (!sha || await gh.branchHead(base) !== sha) return { ok: false, message: "default branch moved since checkout; re-run" };
  return { ok: true, base, sha };
}

// action/src/github.ts
var API = "https://api.github.com";
var MAX_PAGES = 10;
var WRITE_ROLES = /* @__PURE__ */ new Set(["admin", "maintain", "write"]);
function toPr(p) {
  return {
    number: p.number,
    nodeId: p.node_id,
    title: p.title,
    body: p.body ?? "",
    state: p.state,
    draft: p.draft ?? false,
    author: p.user?.login ?? "",
    authorType: p.user?.type ?? "",
    labels: (p.labels ?? []).map((l) => l.name),
    headRef: p.head.ref,
    headSha: p.head.sha,
    baseRef: p.base.ref,
    baseSha: p.base.sha,
    autoMerge: p.auto_merge !== null && p.auto_merge !== void 0
  };
}
function nextLink(link) {
  if (!link) return null;
  for (const part of link.split(",")) {
    const m = /<([^>]+)>\s*;\s*rel="?next"?/.exec(part);
    if (m) return m[1];
  }
  return null;
}
function github(f, token, repo, opts = {}) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new Error(`repo must be owner/name, got ${JSON.stringify(repo)}`);
  const owner = repo.slice(0, repo.indexOf("/"));
  const R = `/repos/${repo}`;
  const secrets = [token];
  const lc = (s) => (s ?? "").toLowerCase();
  const isMine = (u) => opts.selfLogin ? u?.login === opts.selfLogin : u?.type === "Bot";
  async function rest(method, pathOrUrl, body) {
    const url = pathOrUrl.startsWith("https://") ? pathOrUrl : `${API}${pathOrUrl}`;
    const u = new URL(url);
    if (u.origin !== API) throw new Error(`GitHub: refusing to send credentials to another host (${u.host})`);
    const headers = {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "decant-action"
    };
    if (body !== void 0) headers["content-type"] = "application/json";
    const label = `GitHub ${method} ${u.pathname}`;
    const res = await request(f, url, { method, headers, body: body === void 0 ? void 0 : JSON.stringify(body) }, { label, timeoutMs: TIMEOUT_MS, secrets });
    if (!res.ok) throw await httpError(res, { label, secrets });
    return res;
  }
  async function json(method, path, body) {
    return readJson(await rest(method, path, body), `GitHub ${method} ${path}`);
  }
  async function findPaged(path, match) {
    let url = path;
    for (let page = 0; url; page++) {
      if (page >= MAX_PAGES) return { hit: null, capped: true };
      const res = await rest("GET", url);
      const hit = (await readJson(res, `GitHub GET ${path}`)).find(match);
      if (hit) return { hit, capped: false };
      url = nextLink(res.headers.get("link"));
    }
    return { hit: null, capped: false };
  }
  async function paged(path) {
    const out = [];
    let url = path;
    for (let page = 0; url; page++) {
      if (page >= MAX_PAGES) throw new Error(`GitHub GET ${path.split("?")[0]}: more than ${MAX_PAGES} pages`);
      const res = await rest("GET", url);
      out.push(...await readJson(res, `GitHub GET ${path}`));
      url = nextLink(res.headers.get("link"));
    }
    return out;
  }
  async function graphql(query, variables) {
    const r = await json("POST", "/graphql", { query, variables });
    if (r.errors?.length) throw new Error(`GitHub GraphQL: ${r.errors.map((e) => e.message ?? "error").join("; ")}`.replaceAll(token, "***"));
    if (!r.data) throw new Error("GitHub GraphQL: no data");
    return r.data;
  }
  async function writerCanAct(login) {
    let r;
    try {
      r = await json("GET", `${R}/collaborators/${encodeURIComponent(login)}/permission`);
    } catch (e) {
      if (/HTTP 404/.test(e.message)) return false;
      throw e;
    }
    return WRITE_ROLES.has(r.permission ?? "") || WRITE_ROLES.has(r.role_name ?? "");
  }
  async function editMine(n, marker, text) {
    const { hit, capped } = await findPaged(
      `${R}/issues/${n}/comments?per_page=100`,
      (c) => isMine(c.user) && (c.body ?? "").includes(marker)
    );
    if (capped) warning(`decant: #${n} has more than ${MAX_PAGES} pages of comments; the report comment was not found`);
    if (!hit) return null;
    await rest("PATCH", `${R}/issues/comments/${hit.id}`, { body: text });
    return hit.id;
  }
  async function findIssue(title, labels = []) {
    const match = (i) => i.pull_request === void 0 && i.title === title && isMine(i.user);
    const list = `${R}/issues?state=open&per_page=100`;
    const queries = opts.selfLogin ? [`${list}&creator=${encodeURIComponent(opts.selfLogin)}`] : labels.length ? [`${list}&labels=${encodeURIComponent(labels.join(","))}`, list] : [list];
    for (const q of queries) {
      const r = await findPaged(q, match);
      if (r.capped) warning(`decant: more than ${MAX_PAGES} pages of open issues; may create a duplicate of "${title}"`);
      if (r.hit) return r.hit.number;
    }
    return null;
  }
  return {
    graphql,
    /** True if `u` is the account this client acts as (see isMine above). */
    isMine: (u) => isMine(u),
    /**
     * The files changed between `base` and `head` if `head` is exactly one commit on top of `base`,
     * authored by us; otherwise null.
     */
    async ownSingleCommit(base, head) {
      const r = await json(
        "GET",
        `${R}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`
      );
      if (r.status !== "ahead" || r.ahead_by !== 1 || r.behind_by !== 0 || r.commits?.length !== 1) return null;
      const c = r.commits[0];
      if (!isMine(c.author) || c.parents?.length !== 1 || c.parents[0].sha !== base) return null;
      return (r.files ?? []).map((f2) => f2.filename);
    },
    async defaultBranch() {
      return (await json("GET", R)).default_branch;
    },
    async getPr(n) {
      return toPr(await json("GET", `${R}/pulls/${n}`));
    },
    /** Removes `label` from issue/PR `n`; a label that is already gone (404) is not an error. */
    async removeLabel(n, label) {
      try {
        await rest("DELETE", `${R}/issues/${n}/labels/${encodeURIComponent(label)}`);
      } catch (e) {
        if (!/HTTP 404/.test(e.message)) throw e;
      }
    },
    async prLabels(n) {
      return (await paged(`${R}/issues/${n}/labels?per_page=100`)).map((l) => l.name);
    },
    /**
     * True if `label` is on the PR now, its most recent `labeled` event has no later `unlabeled`,
     * and that event's actor has admin, maintain or write permission. Label names compare case-insensitively.
     */
    async labelAddedByWriter(n, label) {
      const want = lc(label);
      const current = await paged(`${R}/issues/${n}/labels?per_page=100`);
      if (!current.some((l) => lc(l.name) === want)) return false;
      const events = await paged(
        `${R}/issues/${n}/timeline?per_page=100`
      );
      let adder = null;
      for (const e of events) {
        if (lc(e.label?.name) !== want) continue;
        if (e.event === "labeled") adder = e.actor?.login ?? null;
        else if (e.event === "unlabeled") adder = null;
      }
      return adder !== null && writerCanAct(adder);
    },
    /** Edits the first comment containing `marker`, else posts one. The body always carries the marker. */
    async upsertComment(n, marker, body) {
      const text = body.includes(marker) ? body : `${marker}
${body}`;
      const id = await editMine(n, marker, text);
      if (id !== null) return { id, created: false };
      const c = await json("POST", `${R}/issues/${n}/comments`, { body: text });
      return { id: c.id, created: true };
    },
    /** Edits our comment containing `marker` if there is one; never creates. True if edited. */
    async updateComment(n, marker, body) {
      return await editMine(n, marker, body.includes(marker) ? body : `${marker}
${body}`) !== null;
    },
    async findOpenPr(head) {
      const q = `head=${encodeURIComponent(`${owner}:${head}`)}`;
      const prs = await json("GET", `${R}/pulls?state=open&${q}&per_page=100`);
      return prs[0] ? toPr(prs[0]) : null;
    },
    /** The most recently closed, unmerged PR from `head` (a declined change), or null. */
    async findClosedUnmergedPr(head) {
      const q = `head=${encodeURIComponent(`${owner}:${head}`)}`;
      const prs = await json(
        "GET",
        `${R}/pulls?state=closed&${q}&per_page=100`
      );
      const declined = prs.filter((p) => !p.merged_at).sort((a, b) => (b.closed_at ?? "").localeCompare(a.closed_at ?? "") || b.number - a.number);
      return declined[0] ? { number: declined[0].number, body: declined[0].body ?? "" } : null;
    },
    /** Head commit sha of branch `name`. */
    async branchHead(name) {
      const r = await json("GET", `${R}/git/ref/heads/${name.split("/").map(encodeURIComponent).join("/")}`);
      return r.object.sha;
    },
    /** Force-moves branch `name` to `sha`. */
    async updateRef(name, sha) {
      await rest("PATCH", `${R}/git/refs/heads/${name.split("/").map(encodeURIComponent).join("/")}`, { sha, force: true });
    },
    async updatePr(n, p) {
      await rest("PATCH", `${R}/pulls/${n}`, p.title === void 0 ? { body: p.body } : { title: p.title, body: p.body });
    },
    /** Adds `labels` to issue/PR `n` (existing labels are kept). */
    async addLabels(n, labels) {
      await rest("POST", `${R}/issues/${n}/labels`, { labels });
    },
    /** UTF-8 contents of `path` at `ref`; null if it does not exist there. */
    async fileAt(path, ref) {
      try {
        const r = await json("GET", `${R}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(ref)}`);
        if (r.encoding !== "base64" || typeof r.content !== "string") return null;
        return Buffer.from(r.content, "base64").toString("utf8");
      } catch (e) {
        if (/HTTP 404/.test(e.message)) return null;
        throw e;
      }
    },
    async createBranch(name, fromSha) {
      await rest("POST", `${R}/git/refs`, { ref: `refs/heads/${name}`, sha: fromSha });
    },
    /** One signed commit via createCommitOnBranch. Fails if the branch head is not expectedHeadOid. Returns the new oid. */
    async commitFiles(branch, expectedHeadOid, message, files) {
      const nl = message.indexOf("\n");
      const headline = nl < 0 ? message : message.slice(0, nl);
      const rest_ = nl < 0 ? "" : message.slice(nl + 1).replace(/^\n+/, "");
      const input = {
        branch: { repositoryNameWithOwner: repo, branchName: branch },
        expectedHeadOid,
        message: rest_ ? { headline, body: rest_ } : { headline },
        fileChanges: { additions: files.map((x) => ({ path: x.path, contents: Buffer.from(x.contents, "utf8").toString("base64") })) }
      };
      const d = await graphql(
        "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }",
        { input }
      );
      return d.createCommitOnBranch.commit.oid;
    },
    async openPr(p) {
      const pr = await json("POST", `${R}/pulls`, {
        head: p.head,
        base: p.base,
        title: p.title,
        body: p.body
      });
      if (p.labels?.length) await rest("POST", `${R}/issues/${pr.number}/labels`, { labels: p.labels });
      return { number: pr.number, nodeId: pr.node_id, url: pr.html_url };
    },
    async enableAutoMerge(prNodeId, method = "SQUASH") {
      await graphql(
        "mutation($id: ID!, $method: PullRequestMergeMethod!) { enablePullRequestAutoMerge(input: { pullRequestId: $id, mergeMethod: $method }) { clientMutationId } }",
        { id: prNodeId, method }
      );
    },
    async disableAutoMerge(prNodeId) {
      await graphql("mutation($id: ID!) { disablePullRequestAutoMerge(input: { pullRequestId: $id }) { clientMutationId } }", { id: prNodeId });
    },
    /** Our open issue titled exactly `title` (see upsertIssue for the search order); null if none. */
    findIssue,
    /**
     * Updates the body of our open issue titled exactly `title`, else creates it with `labels`.
     * Matches on title and author only (not labels), so a removed label never causes a duplicate.
     */
    async upsertIssue(title, body, labels) {
      const hit = await findIssue(title, labels);
      if (hit !== null) {
        await rest("PATCH", `${R}/issues/${hit}`, { body });
        return { number: hit, created: false };
      }
      const i = await json("POST", `${R}/issues`, { title, body, labels });
      return { number: i.number, created: true };
    },
    async closeIssue(n) {
      await rest("PATCH", `${R}/issues/${n}`, { state: "closed", state_reason: "completed" });
    }
  };
}

// action/src/lockfiles.ts
var NPM_REGISTRY = "https://registry.npmjs.org/";
var SKIP_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", "vendor"]);
var LOCKFILES = /* @__PURE__ */ new Set(["package-lock.json", "go.sum"]);
async function findLockfileTree(root, fs) {
  const files = [];
  const symlinks = [];
  const base = root.replace(/\/+$/, "");
  async function walk(rel) {
    const entries = await fs.readdir(rel ? `${base}/${rel}` : base);
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymlink) {
        if (e.isDir || LOCKFILES.has(e.name)) symlinks.push({ path: r, dir: e.isDir });
        continue;
      }
      if (e.isDir) {
        if (!SKIP_DIRS.has(e.name)) await walk(r);
      } else if (LOCKFILES.has(e.name)) {
        files.push(r);
      }
    }
  }
  await walk("");
  const byPath = (a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  return { files: files.sort(), symlinks: symlinks.sort(byPath) };
}
function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
}
function decantPrefix(decantUrl) {
  return new RegExp(`^${escapeRe(decantUrl.replace(/\/+$/, ""))}(/r/[A-Za-z0-9._-]{1,64})?/npm/`);
}
function tarballMatches(resolved, name, version) {
  let path;
  try {
    path = decodeURIComponent(new URL(resolved).pathname);
  } catch {
    return false;
  }
  const base = name.slice(name.lastIndexOf("/") + 1);
  return path === `/${name}/-/${base}-${version}.tgz`;
}
function parsePackageLock(text, file, decantUrl) {
  const lock = JSON.parse(text);
  if (!lock.packages || (lock.lockfileVersion ?? 1) < 2) {
    throw new Error("regenerate package-lock.json with npm 7 or newer");
  }
  const prefix = decantUrl ? decantPrefix(decantUrl) : null;
  const deps = [];
  for (const [key2, entry2] of Object.entries(lock.packages)) {
    if (key2 === "" || entry2.link || entry2.inBundle) continue;
    const idx = key2.lastIndexOf("node_modules/");
    if (idx < 0) continue;
    const name = entry2.name ?? key2.slice(idx + "node_modules/".length);
    const resolved = entry2.resolved;
    const registry = !!entry2.version && (resolved === void 0 || resolved.startsWith(NPM_REGISTRY) || (prefix?.test(resolved) ?? false));
    const dep = { eco: "npm", name, version: entry2.version ?? "", file, source: registry ? "registry" : "other" };
    if (resolved !== void 0) dep.resolved = prefix ? resolved.replace(prefix, NPM_REGISTRY) : resolved;
    if (entry2.integrity !== void 0) dep.integrity = entry2.integrity;
    if (dep.source === "registry" && dep.resolved !== void 0 && !tarballMatches(dep.resolved, name, dep.version)) {
      dep.source = "other";
      dep.mismatch = true;
    }
    deps.push(dep);
  }
  return deps;
}
function parseGoSum(text, file) {
  const seen = /* @__PURE__ */ new Set();
  const deps = [];
  for (const line2 of text.split(/\r?\n/)) {
    const parts = line2.trim().split(/\s+/);
    if (parts.length !== 3) continue;
    const [name, version, hash] = parts;
    if (version.endsWith("/go.mod") || !version.startsWith("v") || !hash.startsWith("h1:")) continue;
    const k = `${name}@${version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    deps.push({ eco: "go", name, version, file, source: "registry" });
  }
  return deps;
}
var key = (d) => d.eco === "npm" ? `npm:${d.name}@${d.version}|${d.source}|${d.resolved ?? ""}|${d.integrity ?? ""}` : `${d.eco}:${d.name}@${d.version}`;
function diffDeps(base, head) {
  const have = new Set(base.map(key));
  const out = /* @__PURE__ */ new Map();
  for (const d of head) {
    const k = key(d);
    if (!have.has(k) && !out.has(k)) out.set(k, d);
  }
  return [...out].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, d]) => d);
}
function resolvedRe(decantUrl) {
  return new RegExp(`("resolved"\\s*:\\s*")${escapeRe(decantUrl.replace(/\/+$/, ""))}(?:/r/[A-Za-z0-9._-]{1,64})?/npm/`, "g");
}
function normalizeLockfile(text, decantUrl) {
  let changed = 0;
  const out = text.replace(resolvedRe(decantUrl), (_m, head) => {
    changed++;
    return `${head}${NPM_REGISTRY}`;
  });
  return { text: out, changed };
}
function containsDecantUrls(text, decantUrl) {
  return new RegExp(resolvedRe(decantUrl).source).test(text);
}

// src/go/escape.ts
function escapeModulePath(p) {
  return p.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

// action/src/registries.ts
var NPM = "https://registry.npmjs.org";
var GOPROXY = "https://proxy.golang.org";
function toDate(v) {
  if (typeof v !== "string") return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}
async function npmPublishTime(f, name, version) {
  const label = `npm registry GET ${name}`;
  const res = await request(f, `${NPM}/${name.replace("/", "%2f")}`, { headers: { accept: "application/json" } }, { label, timeoutMs: TIMEOUT_MS });
  if (res.status === 404) return null;
  if (!res.ok) throw await httpError(res, { label });
  const doc = await readJson(res, label);
  return toDate(doc.time?.[version]);
}
async function goPublishTime(f, module, version) {
  const label = `Go proxy GET ${module}@${version}.info`;
  const url = `${GOPROXY}/${escapeModulePath(module)}/@v/${escapeModulePath(version)}.info`;
  const res = await request(f, url, {}, { label, timeoutMs: TIMEOUT_MS });
  if (res.status === 404 || res.status === 410) return null;
  if (!res.ok) throw await httpError(res, { label });
  const info = await readJson(res, label);
  return toDate(info.Time);
}

// action/src/modes/adopt.ts
var BRANCH = "decant/adopt";
var SCHEMA = "https://raw.githubusercontent.com/sudarkoff/decant/main/schema/policy.json";
var MAX_DEPS = 5e3;
var CONCURRENCY = 8;
var DAY = 864e5;
var safe = (s) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, "?");
var ymd = (d) => d.toISOString().slice(0, 10);
function defaultProject(repo) {
  return repo.slice(repo.indexOf("/") + 1).toLowerCase();
}
async function run({ deps, inputs }) {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.githubToken);
  const stop = (msg) => {
    setOutput("result", "fail", env);
    error(msg);
    process.stderr.write(`${msg}
`);
    return 1;
  };
  if (!inputs.githubToken) return stop("github-token is required");
  const repo = env.GITHUB_REPOSITORY ?? "";
  const wd = inputs.workingDirectory;
  const policyAbs = join(wd, inputs.policyPath);
  const root = env.GITHUB_WORKSPACE || (isAbsolute(wd) ? wd : process.cwd());
  const repoPath = (abs) => relative(resolve(root), resolve(root, abs)).split("\\").join("/");
  const policyRel = repoPath(policyAbs);
  if (policyRel.startsWith("..")) return stop(`${policyAbs} is outside the repository`);
  let raw;
  let cooldownDays = 7;
  let existing = [];
  const hadPolicy = await deps.fs.exists(policyAbs);
  if (hadPolicy) {
    let json;
    try {
      json = JSON.parse(await deps.fs.readFile(policyAbs));
    } catch (e) {
      return stop(`${policyAbs} is not valid JSON: ${e.message}`);
    }
    const parsed = parsePolicy(json);
    if (!parsed.ok) return stop(`invalid policy:
${parsed.errors.map((m) => `- ${m}`).join("\n")}`);
    raw = json;
    cooldownDays = parsed.policy.cooldownDays;
    existing = parsed.policy.allow;
  } else {
    const project = inputs.project || defaultProject(repo);
    if (!PROJECT_ID_RE.test(project)) {
      return stop(
        `project ${JSON.stringify(project)} is not a valid decant project id (must match ${PROJECT_ID_RE.source}); set the project input to your decant project`
      );
    }
    raw = {
      $schema: SCHEMA,
      project,
      cooldownDays,
      allow: [],
      block: []
    };
  }
  const tree = await findLockfileTree(wd, deps.fs);
  if (tree.symlinks.length) {
    for (const l of tree.symlinks) {
      const msg = `${join(wd, l.path)}: ${l.dir ? "symlinked directory" : "lockfile is a symlink"}; not supported`;
      error(msg);
      process.stderr.write(`${msg}
`);
    }
    return stop(`${tree.symlinks.length} symlink(s) in ${wd}; decant does not adopt through symlinks`);
  }
  const all = [];
  const changedFiles = [];
  for (const rel of tree.files) {
    const abs = join(wd, rel);
    const text = await deps.fs.readFile(abs);
    try {
      if (rel.endsWith("package-lock.json")) {
        all.push(...parsePackageLock(text, rel, inputs.decantUrl || void 0));
        const n = inputs.decantUrl ? normalizeLockfile(text, inputs.decantUrl) : { text, changed: 0 };
        if (n.changed > 0) changedFiles.push({ path: repoPath(abs), contents: n.text });
      } else {
        all.push(...parseGoSum(text, rel));
      }
    } catch (e) {
      return stop(`${abs}: ${e.message}`);
    }
  }
  const have = new Set(existing.map((a) => a.package));
  const todo = /* @__PURE__ */ new Map();
  const notGated = /* @__PURE__ */ new Set();
  for (const d of all) {
    const id = formatPackageId(d);
    if (d.source !== "registry") {
      notGated.add(id);
      continue;
    }
    if (!have.has(id) && !todo.has(id)) todo.set(id, d);
  }
  if (todo.size > MAX_DEPS) return stop(`too many dependencies to adopt (${todo.size})`);
  const now = deps.now();
  const items = [...todo];
  const published = /* @__PURE__ */ new Map();
  const failures = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, items.length) }, async () => {
      while (next < items.length) {
        const [id, d] = items[next++];
        try {
          const t = d.eco === "npm" ? await npmPublishTime(deps.fetch, d.name, d.version) : await goPublishTime(deps.fetch, d.name, d.version);
          if (!t) failures.push(`${safe(id)}: publish time not found on the public registry`);
          else published.set(id, t);
        } catch (e) {
          failures.push(`${safe(id)}: ${e.message}`);
        }
      }
    })
  );
  if (failures.length) return stop(`cannot adopt, publish-time lookup failed:
${failures.sort().map((m) => `- ${m}`).join("\n")}`);
  const added = [];
  for (const [id] of items) {
    const at = published.get(id);
    if (now.getTime() - at.getTime() < cooldownDays * DAY) added.push({ id, at });
  }
  added.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const today = ymd(now);
  const allow = [...raw.allow ?? [], ...added.map((a) => ({ package: a.id, reason: "adopted", added: today }))];
  raw = { ...raw, allow };
  const final = parsePolicy(raw);
  if (!final.ok) return stop(`invalid policy:
${final.errors.map((m) => `- ${m}`).join("\n")}`);
  const files = [...changedFiles];
  if (added.length || !hadPolicy) files.unshift({ path: policyRel, contents: `${JSON.stringify(raw, null, 2)}
` });
  if (!files.length) {
    notice("nothing to adopt");
    setOutput("result", "pass", env);
    return 0;
  }
  const body = prBody(added, cooldownDays, [...notGated].sort(), changedFiles.length);
  try {
    const gh = github(deps.fetch, inputs.githubToken, repo, { selfLogin: env.DECANT_GITHUB_LOGIN || void 0 });
    const co = await defaultHeadCheckout(gh, env, "adopt");
    if (!co.ok) return stop(co.message);
    const base = co.base;
    const open = await gh.findOpenPr(BRANCH);
    let head;
    if (open) head = open.headSha;
    else {
      head = co.sha;
      try {
        await gh.createBranch(BRANCH, head);
      } catch (e) {
        if (!/HTTP 422/.test(e.message)) throw e;
        await gh.updateRef(BRANCH, head);
      }
    }
    if (open) {
      let same = true;
      for (const f of files) if (await gh.fileAt(f.path, head) !== f.contents) same = false;
      if (same) {
        notice("adopt PR already up to date");
        setOutput("pr-number", String(open.number), env);
        setOutput("result", "pass", env);
        return 0;
      }
    }
    await gh.commitFiles(BRANCH, head, "decant: adopt", files);
    if (open) {
      await gh.updatePr(open.number, { body });
      notice(`updated #${open.number}`);
      setOutput("pr-number", String(open.number), env);
    } else {
      const pr = await gh.openPr({ head: BRANCH, base, title: "decant: adopt", body, labels: ["decant:adopt"] });
      notice(`opened ${pr.url}`);
      setOutput("pr-number", String(pr.number), env);
    }
  } catch (e) {
    return stop(`decant adopt: ${e.message}`);
  }
  setOutput("result", "pass", env);
  return 0;
}
function prBody(added, cooldownDays, notGated, normalized) {
  const lines = [
    "One-time adoption of decant. Review, then merge.",
    "",
    `Versions already in your lockfiles that are still inside the ${cooldownDays}-day cooldown get an allow entry, so installs keep working on day one.`
  ];
  if (added.length) {
    lines.push("", "| package | published | ages out |", "| --- | --- | --- |");
    for (const a of added) lines.push(`| ${safe(a.id)} | ${ymd(a.at)} | ${ymd(new Date(a.at.getTime() + cooldownDays * DAY))} |`);
  } else lines.push("", "No versions are inside the cooldown; no allow entries needed.");
  if (normalized) lines.push("", `${normalized} lockfile(s) normalized to registry.npmjs.org URLs.`);
  if (notGated.length) {
    lines.push("", "**not gated by decant** (not from the public registry):", "", ...notGated.map((id) => `- ${safe(id)}`));
  }
  lines.push("", "**Next steps:** merge this PR; the sync on the default branch then applies the policy.");
  return lines.join("\n");
}

// action/src/modes/audit.ts
var audit_exports = {};
__export(audit_exports, {
  auditSetHash: () => auditSetHash,
  overrideKey: () => overrideKey,
  run: () => run2
});
import { createHash as createHash2, randomUUID as randomUUID2 } from "node:crypto";
import { dirname, isAbsolute as isAbsolute2, join as join3, relative as relative2, resolve as resolve2 } from "node:path";

// src/semver.ts
var NUM = "(0|[1-9]\\d*)";
var PRE_ID = "(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)";
var RE = new RegExp(
  `^${NUM}\\.${NUM}\\.${NUM}(?:-(${PRE_ID}(?:\\.${PRE_ID})*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`
);
function parseVersion(v, eco) {
  let s = v;
  if (eco === "go") {
    if (!s.startsWith("v")) return null;
    s = s.slice(1);
  }
  const m = RE.exec(s);
  if (!m) return null;
  const [major, minor, patch] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return { major, minor, patch, pre: m[4] ? m[4].split(".") : [] };
}
var isNum = (s) => /^\d+$/.test(s);
function cmpId(a, b) {
  const an = isNum(a);
  const bn = isNum(b);
  if (an && bn) {
    const x = BigInt(a);
    const y = BigInt(b);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  if (an) return -1;
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}
function cmpParsed(a, b) {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  if (a.pre.length === 0 || b.pre.length === 0) {
    return a.pre.length === b.pre.length ? 0 : a.pre.length === 0 ? 1 : -1;
  }
  const n = Math.min(a.pre.length, b.pre.length);
  for (let i = 0; i < n; i++) {
    const c = cmpId(a.pre[i], b.pre[i]);
    if (c !== 0) return c;
  }
  return a.pre.length === b.pre.length ? 0 : a.pre.length < b.pre.length ? -1 : 1;
}
function compareVersions(a, b, eco) {
  const pa = parseVersion(a, eco);
  const pb = parseVersion(b, eco);
  if (!pa || !pb) return pa ? 1 : pb ? -1 : 0;
  return cmpParsed(pa, pb);
}

// action/src/audit-images.ts
import { join as join2 } from "node:path";

// src/oci.ts
var MANIFEST_ACCEPT = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json"
].join(", ");
var REGISTRIES = {
  "docker.io": {
    api: "https://registry-1.docker.io",
    token: (path) => `https://auth.docker.io/token?${new URLSearchParams({ service: "registry.docker.io", scope: `repository:${path}:pull` })}`
  },
  "ghcr.io": {
    api: "https://ghcr.io",
    token: (path) => `https://ghcr.io/token?${new URLSearchParams({ service: "ghcr.io", scope: `repository:${path}:pull` })}`
  }
};
var isKnownRegistry = (registry) => Object.hasOwn(REGISTRIES, registry);
function splitRepo(name) {
  const i = name.indexOf("/");
  return { registry: name.slice(0, i), path: name.slice(i + 1) };
}
var TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
var MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
async function readCapped(res, max) {
  if (Number(res.headers.get("content-length") ?? "0") > max) {
    await res.body?.cancel().catch(() => {
    });
    return null;
  }
  if (!res.body) return new ArrayBuffer(0);
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {
      });
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out.buffer;
}
async function sha256(bytes) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return `sha256:${[...h].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}
function ociClient(o) {
  const timeoutMs = o.timeoutMs ?? 1e4;
  const tokens = /* @__PURE__ */ new Map();
  async function get(url, init = {}) {
    return o.fetch(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
  }
  async function token(registry, reg, path) {
    const key2 = `${registry}/${path}`;
    let t = tokens.get(key2);
    if (!t) {
      t = (async () => {
        const res = await get(reg.token(path));
        if (res.status === 401 || res.status === 403) return "denied";
        if (!res.ok || res.status >= 300) throw new Error(`token endpoint HTTP ${res.status}`);
        const body = await res.json();
        const v = typeof body.token === "string" ? body.token : typeof body.access_token === "string" ? body.access_token : "";
        if (!v) throw new Error("token endpoint returned no token");
        return v;
      })();
      tokens.set(key2, t);
      t.catch(() => tokens.delete(key2));
    }
    return t;
  }
  async function manifest(name, reference) {
    const { registry, path } = splitRepo(name);
    const reg = REGISTRIES[registry];
    if (!reg) return { status: "unsupported" };
    const byDigest = DIGEST_RE.test(reference);
    if (!byDigest && !TAG_RE.test(reference)) return { status: "error", message: "invalid tag" };
    try {
      const t = await token(registry, reg, path);
      if (t === "denied") return { status: "denied" };
      const url = `${reg.api}/v2/${path}/manifests/${reference}`;
      const headers = { accept: MANIFEST_ACCEPT, authorization: `Bearer ${t}` };
      let res = await get(url, { method: "HEAD", headers });
      if (res.status === 404) return { status: "not-found" };
      if (res.status === 401 || res.status === 403) return { status: "error", message: `HTTP ${res.status} with an anonymous token` };
      if (!res.ok || res.status >= 300) return { status: "error", message: `HTTP ${res.status}` };
      let digest = res.headers.get("docker-content-digest");
      if (digest === null) {
        res = await get(url, { headers });
        if (res.status === 404) return { status: "not-found" };
        if (!res.ok || res.status >= 300) return { status: "error", message: `HTTP ${res.status}` };
        const body = await readCapped(res, MAX_MANIFEST_BYTES);
        if (body === null) return { status: "error", message: "manifest larger than 4 MB" };
        digest = await sha256(body);
      }
      if (!DIGEST_RE.test(digest)) return { status: "error", message: "registry returned a malformed digest" };
      if (byDigest && digest !== reference) return { status: "error", message: "registry returned a different digest" };
      return { status: "ok", digest };
    } catch (e) {
      const err = e;
      return { status: "error", message: ["TimeoutError", "AbortError"].includes(err?.name) ? "timed out" : String(err?.message ?? e) };
    }
  }
  return {
    manifest,
    /** The digest a tag currently resolves to. */
    resolveTag: (name, tag) => manifest(name, tag),
    /** Whether the registry serves this digest. */
    verifyDigest: (name, digest) => manifest(name, digest)
  };
}

// action/src/dockerfile.ts
var TAG_RE2 = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
function parseImageRef(ref) {
  if (ref === "" || /\s/.test(ref)) return null;
  const parts = ref.split("@");
  if (parts.length > 2) return null;
  const digest = parts[1];
  if (digest !== void 0 && !DIGEST_RE.test(digest)) return null;
  let rest = parts[0];
  let tag;
  const colon = rest.lastIndexOf(":");
  if (colon > rest.lastIndexOf("/")) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
    if (!TAG_RE2.test(tag)) return null;
  }
  const comps = rest.split("/");
  let registry = "docker.io";
  const first = comps[0];
  if (comps.length > 1 && (first.includes(".") || first.includes(":") || first === "localhost")) {
    registry = DOCKER_HUB_ALIASES.has(first) ? "docker.io" : first;
    comps.shift();
  } else if (comps.length === 1 && first.includes(".")) {
    return null;
  }
  if (registry === "docker.io" && comps.length === 1) comps.unshift("library");
  const path = comps.join("/");
  const name = `${registry}/${path}`;
  if (!isImageRepo(name)) return null;
  return { name, registry, path, ...tag !== void 0 ? { tag } : {}, ...digest !== void 0 ? { digest } : {} };
}
var DIRECTIVE_RE = /^#\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.+?)\s*$/;
var DIRECTIVES = /* @__PURE__ */ new Set(["syntax", "escape", "check"]);
var HEREDOC_INSTRUCTIONS = /* @__PURE__ */ new Set(["RUN", "COPY", "ADD"]);
var INSTRUCTIONS = /* @__PURE__ */ new Set([
  "FROM",
  "RUN",
  "CMD",
  "LABEL",
  "MAINTAINER",
  "EXPOSE",
  "ENV",
  "ADD",
  "COPY",
  "ENTRYPOINT",
  "VOLUME",
  "USER",
  "WORKDIR",
  "ARG",
  "ONBUILD",
  "STOPSIGNAL",
  "HEALTHCHECK",
  "SHELL"
]);
var STAGE_RE = /^[a-z][a-z0-9_.-]*$/;
var HEREDOC_WORD = /^(\d*)<<(-?)(["']?)([A-Za-z0-9_.-]+)\3$/;
function shellWords(s, esc) {
  const words = [];
  let cur = "";
  let inWord = false;
  let q = null;
  for (let k = 0; k < s.length; k++) {
    const ch = s[k];
    if (q === "'") {
      cur += ch;
      if (ch === "'") q = null;
      continue;
    }
    if (ch === esc) {
      cur += ch + (s[k + 1] ?? "");
      k++;
      inWord = true;
      continue;
    }
    if (q === '"') {
      cur += ch;
      if (ch === '"') q = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      q = ch;
      cur += ch;
      inWord = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (inWord) words.push(cur);
      cur = "";
      inWord = false;
      continue;
    }
    cur += ch;
    inWord = true;
  }
  if (q !== null) return null;
  if (inWord) words.push(cur);
  return words;
}
function heredocs(ins, esc) {
  const a = shellWords(ins, "\\");
  const b = esc === "\\" ? a : shellWords(ins, esc);
  if (a === null || b === null || a.length !== b.length || a.some((w, k) => w !== b[k])) return "decant couldn't parse this line (heredoc)";
  const out = [];
  for (const w of a) {
    if (!w.includes("<<")) continue;
    const m = HEREDOC_WORD.exec(w);
    if (!m) return "decant couldn't parse this line (heredoc)";
    out.push({ word: m[4], strip: m[2] === "-" });
  }
  return out;
}
var VAR_RE = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))/g;
function unquote(v) {
  return v.length >= 2 && (v[0] === '"' || v[0] === "'") && v.at(-1) === v[0] ? v.slice(1, -1) : v;
}
function substitute(s, args) {
  const missing = [];
  const used = [];
  const text = s.replace(VAR_RE, (_m, braced, op, word, bare) => {
    const n = braced ?? bare;
    if (!used.includes(n)) used.push(n);
    const v = args.get(n)?.value;
    if (op === void 0) {
      if (v === void 0) {
        if (!missing.includes(n)) missing.push(n);
        return "";
      }
      return v;
    }
    const w = word ?? "";
    switch (op) {
      case ":-":
        return v === void 0 || v === "" ? w : v;
      case "-":
        return v === void 0 ? w : v;
      case ":+":
        return v !== void 0 && v !== "" ? w : "";
      default:
        return v !== void 0 ? w : "";
    }
  });
  return { text, missing, used };
}
function parseDockerfile(text) {
  const lines = text.replace(/^﻿/, "").split(/\r?\n/);
  const froms = [];
  const errors = [];
  const directives = /* @__PURE__ */ new Map();
  let i = 0;
  for (; i < lines.length; i++) {
    const m = DIRECTIVE_RE.exec(lines[i].trim());
    if (!m || !DIRECTIVES.has(m[1].toLowerCase())) break;
    const k = m[1].toLowerCase();
    if (directives.has(k)) errors.push(`line ${i + 1}: parser directive ${k} is repeated`);
    else directives.set(k, { value: m[2], line: i + 1 });
  }
  let escape = "\\";
  const esc = directives.get("escape");
  if (esc) {
    if (esc.value === "`" || esc.value === "\\") escape = esc.value;
    else errors.push(`line ${esc.line}: invalid escape directive (BuildKit accepts \\ or \`)`);
  }
  const syn = directives.get("syntax");
  if (syn) {
    const ref = parseImageRef(syn.value);
    if (ref) froms.push({ line: syn.line, kind: "image", raw: syn.value, text: syn.value, ref, syntax: true });
    else {
      errors.push(`line ${syn.line}: syntax=${syn.value}: not a valid image reference`);
      froms.push({ line: syn.line, kind: "invalid", raw: syn.value, text: "", syntax: true });
    }
  }
  const instructions = [];
  let cur = null;
  for (; i < lines.length; i++) {
    const physical = lines[i];
    const t = physical.trim();
    if (t === "" || t.startsWith("#")) continue;
    const trimmedEnd = physical.replace(/\s+$/, "");
    const continued = trimmedEnd.endsWith(escape);
    const body = continued ? trimmedEnd.slice(0, -1) : trimmedEnd;
    if (cur === null) cur = { line: i + 1, parts: [] };
    cur.parts.push(body.trim());
    if (continued) continue;
    const ins = { line: cur.line, text: cur.parts.join(" ").trim() };
    cur = null;
    const toks = ins.text.split(/\s+/);
    const word = toks[0].toUpperCase();
    if (!INSTRUCTIONS.has(word)) {
      errors.push(`line ${ins.line}: decant couldn't parse this line (${toks[0].slice(0, 40)} is not a Dockerfile instruction)`);
      continue;
    }
    const inner = word === "ONBUILD" ? (toks[1] ?? "").toUpperCase() : "";
    if (word === "ONBUILD" && (!INSTRUCTIONS.has(inner) || inner === "ONBUILD" || inner === "FROM" || inner === "MAINTAINER")) {
      errors.push(`line ${ins.line}: decant couldn't parse this line (ONBUILD ${(toks[1] ?? "").slice(0, 40)} is not allowed)`);
      continue;
    }
    instructions.push(ins);
    if (!ins.text.includes("<<")) continue;
    if (!HEREDOC_INSTRUCTIONS.has(word) && !HEREDOC_INSTRUCTIONS.has(inner)) continue;
    const docs = heredocs(ins.text, escape);
    if (typeof docs === "string") {
      errors.push(`line ${ins.line}: ${docs}`);
      return { froms, errors };
    }
    for (const d of docs) {
      let j = i + 1;
      while (j < lines.length && (d.strip ? lines[j].replace(/^\t+/, "") : lines[j]) !== d.word) j++;
      if (j >= lines.length) {
        errors.push(`line ${ins.line}: heredoc <<${d.word} is never terminated`);
        return { froms, errors };
      }
      i = j;
    }
  }
  if (cur !== null) errors.push(`line ${cur.line}: decant couldn't parse this line (the file ends inside a line continuation)`);
  const firstIns = instructions[0]?.line ?? lines.length + 1;
  for (let k = 0; k < Math.min(firstIns - 1, lines.length); k++) {
    if (k + 1 === syn?.line) continue;
    if (/syntax\s*[=:]|"syntax"/i.test(lines[k])) {
      errors.push(`line ${k + 1}: ambiguous frontend (syntax) header; use one "# syntax=<image>@sha256:\u2026" directive at the top of the file`);
    }
  }
  const globals = /* @__PURE__ */ new Map();
  let stageArgs = /* @__PURE__ */ new Map();
  const argLines = [];
  const stages = /* @__PURE__ */ new Set();
  let seenFrom = false;
  for (const ins of instructions) {
    const m = /^(\S+)\s*(.*)$/.exec(ins.text);
    if (!m) continue;
    const word = m[1].toUpperCase();
    const rest = m[2];
    if (word === "ARG") {
      const quoted = /["'\\]/.test(rest) || rest.includes(escape);
      const names = (tok) => {
        const eq = tok.indexOf("=");
        return { n: eq < 0 ? tok : tok.slice(0, eq), v: eq < 0 ? void 0 : unquote(tok.slice(eq + 1)) };
      };
      if (seenFrom) {
        for (const tok of rest.split(/\s+/).filter(Boolean)) {
          const { n, v } = names(tok);
          if (quoted) stageArgs.set(n, { value: void 0, opaque: "quoted" });
          else if (v === void 0 && globals.has(n)) stageArgs.set(n, { ...globals.get(n) });
          else stageArgs.set(n, { value: v });
        }
        continue;
      }
      for (const tok of rest.split(/\s+/).filter(Boolean)) {
        const { n, v } = names(tok);
        globals.set(n, quoted ? { value: void 0, opaque: "quoted" } : { value: v });
      }
      continue;
    }
    if (word === "ENV") {
      const named = [...rest.matchAll(/(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=/g)].map((m2) => m2[1]);
      if (!named.length) {
        const legacy = /^([A-Za-z_][A-Za-z0-9_]*)\b/.exec(rest);
        if (legacy) named.push(legacy[1]);
      }
      for (const n of named) stageArgs.set(n, { value: void 0, opaque: "env" });
      continue;
    }
    const inner = word === "ONBUILD" ? /^(\S+)\s*(.*)$/.exec(rest) ?? [] : [];
    const kind = word === "ONBUILD" ? (inner[1] ?? "").toUpperCase() : word;
    if (kind === "COPY" || kind === "RUN") {
      let argsUsed = [];
      for (const src of imageSources(kind, word === "ONBUILD" ? inner[2] ?? "" : rest, escape, stageArgs)) {
        if ("argsUsed" in src) {
          argsUsed = [.../* @__PURE__ */ new Set([...argsUsed, ...src.argsUsed])];
          continue;
        }
        if ("error" in src) {
          errors.push(`line ${ins.line}: decant couldn't parse this line (${src.error})`);
          froms.push({ line: ins.line, kind: "invalid", raw: rest, text: "" });
          continue;
        }
        const v = src.value;
        if (/^\d+$/.test(v) || !/[/:@]/.test(v) && stages.has(v.toLowerCase())) continue;
        const ref = parseImageRef(v);
        if (!ref) {
          errors.push(`line ${ins.line}: ${kind} ${src.flag}=${v}: not an earlier stage or a valid image reference`);
          froms.push({ line: ins.line, kind: "invalid", raw: rest, text: "" });
          continue;
        }
        froms.push({ line: ins.line, kind: "image", raw: rest, text: v, ref, via: src.via });
      }
      if (argsUsed.length) argLines.push({ line: ins.line, args: argsUsed });
      continue;
    }
    if (word !== "FROM") continue;
    seenFrom = true;
    stageArgs = /* @__PURE__ */ new Map();
    const bad = (why) => {
      errors.push(`line ${ins.line}: FROM ${rest}: ${why}`);
      froms.push({ line: ins.line, kind: "invalid", raw: rest, text: "" });
    };
    const toks = rest.split(/\s+/).filter(Boolean);
    let platform;
    let flagError = false;
    while (toks[0]?.startsWith("--")) {
      const f = toks.shift();
      if (/^--platform=\S+$/i.test(f)) platform = f.slice("--platform=".length);
      else flagError = true;
    }
    if (flagError) {
      bad("unsupported FROM flag");
      continue;
    }
    if (toks.length === 0) {
      bad("no image");
      continue;
    }
    let stage;
    if (toks.length === 3 && toks[1].toLowerCase() === "as") {
      stage = toks[2].toLowerCase();
      if (!STAGE_RE.test(stage)) {
        bad(`invalid stage name ${toks[2]}`);
        continue;
      }
    } else if (toks.length !== 1) {
      bad("expected FROM [--platform=\u2026] <image> [AS <name>]");
      continue;
    }
    const raw = toks[0];
    const sub = substitute(raw, globals);
    const opaque = sub.used.filter((n) => globals.get(n)?.opaque);
    if (opaque.length) {
      bad(`decant can't evaluate ${opaque.map((n) => `$${n}`).join(", ")} (its ARG line has quotes or backslashes); use a literal`);
      continue;
    }
    if (sub.missing.length) {
      bad(`${sub.missing.map((n) => `ARG ${n}`).join(", ")} has no default; decant cannot tell which image a build would use`);
      continue;
    }
    const image = sub.text;
    const base = { line: ins.line, raw: rest, text: image, ...platform ? { platform } : {}, ...stage ? { stage } : {}, ...sub.used.length ? { args: sub.used } : {} };
    if (image.toLowerCase() === "scratch") froms.push({ ...base, kind: "scratch" });
    else if (!/[/:@]/.test(image) && stages.has(image.toLowerCase())) froms.push({ ...base, kind: "stage" });
    else {
      const ref = parseImageRef(image);
      if (!ref) {
        bad("not a valid image reference");
        if (stage) stages.add(stage);
        continue;
      }
      froms.push({ ...base, kind: "image", ref });
    }
    if (stage) stages.add(stage);
  }
  const lineOf = (e) => Number(/^line (\d+)/.exec(e)?.[1] ?? 0);
  return { froms, errors: errors.map((e, k) => ({ e, k })).sort((a, b) => lineOf(a.e) - lineOf(b.e) || a.k - b.k).map((x) => x.e), ...argLines.length ? { argLines } : {} };
}
var KNOWN_FLAGS = {
  COPY: /* @__PURE__ */ new Set(["--from", "--chown", "--chmod", "--link", "--parents", "--exclude"]),
  RUN: /* @__PURE__ */ new Set(["--mount", "--network", "--security", "--device"])
};
var PLATFORM_ARGS = new Map(
  ["TARGETPLATFORM", "TARGETOS", "TARGETARCH", "TARGETVARIANT", "BUILDPLATFORM", "BUILDOS", "BUILDARCH", "BUILDVARIANT"].map((n) => [n, "platform"])
);
function expandMount(value, scope) {
  const all = new Map([...[...PLATFORM_ARGS].map(([k, v]) => [k, { value: v }]), ...scope]);
  const sub = substitute(value, all);
  for (const n of sub.used) {
    const o = all.get(n)?.opaque;
    if (o === "env") return { error: `decant can't evaluate $${n} set by ENV in a --mount; use a literal` };
    if (o === "quoted") return { error: `decant can't evaluate $${n} (its ARG line has quotes or backslashes) in a --mount; use a literal` };
  }
  if (sub.missing.length) return { error: `--mount uses ${sub.missing.map((n) => `$${n}`).join(", ")} with no value decant can see` };
  for (const n of sub.used) {
    const v = all.get(n)?.value ?? "";
    if (/[,=]/.test(v)) return { error: `--mount: ARG ${n} has a value with ',' or '='` };
  }
  const raw = value.replace(VAR_RE, "");
  if ((sub.text.match(/[,=]/g) ?? []).length !== (raw.match(/[,=]/g) ?? []).length) return { error: "--mount: a variable expands to ',' or '='" };
  return { text: sub.text, used: sub.used.filter((n) => !PLATFORM_ARGS.has(n) || scope.has(n)) };
}
function imageSources(kind, args, esc, scope) {
  const out = [];
  const odd = (t) => /["'\\]/.test(t) || t.includes(esc);
  for (const tok of args.split(/\s+/).filter(Boolean)) {
    const flagLike = tok.startsWith("--") || odd(tok[0]) && tok.replace(/^["'\\`]+/, "").startsWith("-");
    if (!flagLike) break;
    if (odd(tok)) {
      out.push({ error: `${kind} flag with quotes or escapes` });
      continue;
    }
    const eq = tok.indexOf("=");
    const name = eq < 0 ? tok : tok.slice(0, eq);
    if (!KNOWN_FLAGS[kind].has(name)) {
      out.push({ error: `unknown ${kind} flag ${name.slice(0, 40)}` });
      continue;
    }
    const wanted = kind === "COPY" ? "--from" : "--mount";
    if (name !== wanted) continue;
    const value = eq < 0 ? "" : tok.slice(eq + 1);
    if (eq < 0) {
      out.push({ error: `${tok.slice(0, 40)}: write ${wanted}=\u2026` });
      continue;
    }
    if (kind === "COPY") {
      if (value.includes("$")) out.push({ error: "--from with variables" });
      else out.push({ via: "copy", flag: "--from", value });
      continue;
    }
    const x = expandMount(value, scope);
    if ("error" in x) {
      out.push({ error: x.error });
      continue;
    }
    if (x.used.length) out.push({ argsUsed: x.used });
    for (const kv of x.text.split(",")) {
      const k = kv.indexOf("=");
      if (k < 0 || kv.slice(0, k).toLowerCase() !== "from") continue;
      if (kv.slice(0, k) !== "from") out.push({ error: `--mount ${kv.slice(0, k)}=: write from=` });
      else out.push({ via: "mount", flag: "--mount from", value: kv.slice(k + 1) });
    }
  }
  return out;
}
var SKIP_DIRS2 = /* @__PURE__ */ new Set(["node_modules", ".git", "vendor", "testdata"]);
function isDockerfileName(n) {
  if (n.endsWith(".dockerignore") || n.endsWith(".containerignore")) return false;
  for (const base of ["Dockerfile", "Containerfile"]) {
    if (n === base || n.startsWith(`${base}.`) && n.length > base.length + 1) return true;
  }
  return [".Dockerfile", ".dockerfile", ".containerfile"].some((ext) => n.endsWith(ext) && n.length > ext.length);
}
async function findDockerfiles(root, fs) {
  const files = [];
  const symlinks = [];
  const base = root.replace(/\/+$/, "");
  async function walk(rel) {
    for (const e of await fs.readdir(rel ? `${base}/${rel}` : base)) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymlink) {
        if (e.isDir && !SKIP_DIRS2.has(e.name) || isDockerfileName(e.name)) symlinks.push(r);
        continue;
      }
      if (e.isDir) {
        if (!SKIP_DIRS2.has(e.name)) await walk(r);
      } else if (isDockerfileName(e.name)) files.push(r);
    }
  }
  await walk("");
  return { files: files.sort(), symlinks: symlinks.sort() };
}

// action/src/grype.ts
import { createHash } from "node:crypto";
var GRYPE_VERSION = "0.121.3";
var GRYPE_SHA256 = {
  amd64: "e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85",
  arm64: "b7815598d48da78bfd16f5b98ef28e1bb09c03d34fc8c3e350f99b6ccb3c7cba"
};
var DOWNLOAD_TIMEOUT_MS = 12e4;
var grypeUrl = (arch) => `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${arch}.tar.gz`;
function grypeArch(platform = process.platform, arch = process.arch) {
  if (platform !== "linux") throw new Error(`Grype runs on Linux runners only (this is ${platform})`);
  if (arch === "x64") return "amd64";
  if (arch === "arm64") return "arm64";
  throw new Error(`no pinned Grype build for ${arch}`);
}
function tail(s) {
  return s.trim().split("\n").slice(-5).join(" ").slice(0, 500);
}
async function installGrype(f, exec, fs, dir, arch, expected = GRYPE_SHA256) {
  const url = grypeUrl(arch);
  const res = await request(f, url, { redirect: "follow" }, { label: `download Grype ${GRYPE_VERSION}`, timeoutMs: DOWNLOAD_TIMEOUT_MS });
  if (!res.ok) throw new Error(`download Grype ${GRYPE_VERSION}: HTTP ${res.status}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const got = createHash("sha256").update(bytes).digest("hex");
  if (got !== expected[arch]) throw new Error(`Grype ${GRYPE_VERSION} linux_${arch} checksum mismatch: got ${got}, pinned ${expected[arch]}`);
  await fs.mkdir(dir);
  const tarball = `${dir}/grype.tar.gz`;
  await fs.writeBytes(tarball, bytes);
  const x = await exec("tar", ["-xzf", tarball, "-C", dir, "grype"]);
  if (x.code !== 0) throw new Error(`extracting Grype failed: ${tail(x.stderr)}`);
  return { bin: `${dir}/grype` };
}
function grypeEnv(cacheDir) {
  return {
    GRYPE_DB_CACHE_DIR: cacheDir,
    GRYPE_DB_AUTO_UPDATE: "true",
    GRYPE_DB_REQUIRE_UPDATE_CHECK: "true",
    GRYPE_DB_VALIDATE_AGE: "true",
    GRYPE_CHECK_FOR_APP_UPDATE: "false"
  };
}
var SEV = { critical: "critical", high: "high", medium: "moderate", low: "low", negligible: "low" };
var RANK = { critical: 0, high: 1, moderate: 2, unknown: 3, low: 4 };
var MAX_TEXT = 100;
var clip = (s) => {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > MAX_TEXT ? `${t.slice(0, MAX_TEXT - 1)}\u2026` : t;
};
var isSerious = (f) => f.severity === "critical" || f.severity === "high";
function parseGrypeJson(stdout) {
  let doc;
  try {
    doc = JSON.parse(stdout);
  } catch {
    throw new Error("grype: invalid JSON output");
  }
  if (!doc || !Array.isArray(doc.matches)) throw new Error("grype: no matches in output");
  const seen = /* @__PURE__ */ new Map();
  for (const m of doc.matches) {
    const v = m?.vulnerability;
    const a = m?.artifact;
    if (!v || typeof v.id !== "string" || v.id.trim() === "") throw new Error("grype: a match has no vulnerability id");
    const sev = typeof v.severity === "string" ? SEV[v.severity.toLowerCase()] ?? "unknown" : "unknown";
    const fix = v.fix;
    const fixed = fix?.state === "fixed" && Array.isArray(fix.versions) ? fix.versions.filter((x) => typeof x === "string" && x.trim() !== "") : [];
    const name = typeof a?.name === "string" ? a.name : "?";
    const version = typeof a?.version === "string" ? a.version : "?";
    const where = typeof a?.purl === "string" && a.purl ? a.purl : JSON.stringify(a?.locations ?? null);
    const k = JSON.stringify([v.id, name, version, typeof a?.type === "string" ? a.type : "", where]);
    const prev = seen.get(k);
    if (!prev) {
      seen.set(k, { id: v.id, severity: sev, package: name, version, fixed: [...new Set(fixed)] });
      continue;
    }
    if (RANK[sev] < RANK[prev.severity]) prev.severity = sev;
    prev.fixed = [.../* @__PURE__ */ new Set([...prev.fixed, ...fixed])];
  }
  for (const f of seen.values()) {
    f.id = clip(f.id);
    f.package = clip(f.package);
    f.version = clip(f.version);
    f.fixed = f.fixed.map(clip);
  }
  const findings = [...seen.values()].sort((x, y) => RANK[x.severity] - RANK[y.severity] || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  return { findings, failing: findings.filter((f) => isSerious(f) && f.fixed.length > 0), unfixed: findings.filter((f) => isSerious(f) && f.fixed.length === 0) };
}
var PLATFORM_RE = /^linux\/[a-z0-9]+(?:\/v[0-9]+)?$/;
async function scanImage(exec, bin, name, digest, env, platform) {
  const args = [`registry:${name}@${digest}`, "-o", "json", "-q"];
  if (platform && PLATFORM_RE.test(platform)) args.push("--platform", platform);
  const r = await exec(bin, args, { env });
  if (r.code !== 0) throw new Error(`grype exited ${r.code}: ${tail(r.stderr)}`);
  return parseGrypeJson(r.stdout);
}
var MAX_DETAILS = 100;
function grypeVerdict(r) {
  const serious = r.findings.filter(isSerious).slice(0, MAX_DETAILS);
  return { result: serious.length ? "flagged" : "clean", details: serious };
}

// action/src/audit-images.ts
var IMAGES_REF = "audit-images";
var safe2 = (s) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, "?");
var short = (d) => d.slice(0, "sha256:".length + 12);
var SEV_ORDER = ["critical", "high", "moderate", "low"];
async function auditImages(deps, client, wd, repoPath) {
  const env = deps.env;
  const lines = [];
  const tree = await findDockerfiles(wd, deps.fs);
  for (const l of tree.symlinks) warning(`${safe2(l)}: symlinked Dockerfile or directory; not audited`);
  const groups = /* @__PURE__ */ new Map();
  const texts = /* @__PURE__ */ new Map();
  const unpinned = [];
  for (const rel of tree.files) {
    const text = await deps.fs.readFile(join2(wd, rel));
    texts.set(rel, text);
    const p = parseDockerfile(text);
    if (p.errors.length) lines.push(`- ${safe2(rel)}: ${p.errors.length} line(s) decant cannot read (the PR scan fails on them)`);
    for (const f of p.froms) {
      if (f.kind !== "image" || !f.ref) continue;
      if (!f.ref.digest) {
        unpinned.push(`${safe2(rel)}:${f.line}`);
        continue;
      }
      const k = `${f.ref.name}|${f.ref.tag ?? ""}|${f.ref.digest}`;
      const g = groups.get(k) ?? { name: f.ref.name, tag: f.ref.tag ?? "", digest: f.ref.digest, platform: f.platform, uses: [] };
      g.uses.push({ rel, line: f.line });
      groups.set(k, g);
    }
  }
  if (unpinned.length) lines.push(`- Not pinned by digest: ${unpinned.slice(0, 10).join(", ")}${unpinned.length > 10 ? ", \u2026" : ""}`);
  if (!groups.size) return { bumps: [], files: [], lines };
  let bin = null;
  const grype = () => bin ??= installGrype(deps.fetch, deps.exec, deps.fs, `${env.RUNNER_TEMP}/decant-grype`, grypeArch(env.DECANT_GRYPE_PLATFORM || process.platform, env.DECANT_GRYPE_ARCH || process.arch)).then((g) => g.bin);
  const genv = grypeEnv(`${env.RUNNER_TEMP}/decant-grype-db`);
  const scans = /* @__PURE__ */ new Map();
  const findings = (name, digest, platform) => {
    const k = `${name}@${digest}`;
    let s = scans.get(k);
    if (!s) {
      s = (async () => {
        try {
          const r = await scanImage(deps.exec, await grype(), name, digest, genv, platform);
          const v = grypeVerdict(r);
          await client.putVerdict({ package: formatPackageId({ eco: "docker", name, version: digest }), scanner: "grype", scannerVersion: GRYPE_VERSION, result: v.result, details: v.details });
          return r.findings;
        } catch (e) {
          warning(`${safe2(k)}: ${safe2(e.message).slice(0, 200)}`);
          return null;
        }
      })();
      scans.set(k, s);
    }
    return s;
  };
  const oci = ociClient({ fetch: deps.fetch });
  const candidates = [];
  for (const g of groups.values()) {
    const label = `\`${safe2(g.name)}${g.tag ? `:${safe2(g.tag)}` : ""}@${short(g.digest)}\``;
    if (!isKnownRegistry(g.name.slice(0, g.name.indexOf("/")))) {
      lines.push(`- ${label}: registry not supported; not scanned`);
      continue;
    }
    const all = await findings(g.name, g.digest, g.platform);
    const now = all === null ? null : all.filter(isSerious);
    const state = now === null ? "scan error" : now.length ? `${now.length} High/Critical` : "clean";
    if (!g.tag) {
      lines.push(`- ${label}: ${state}; no tag to follow`);
      continue;
    }
    const r = await oci.resolveTag(g.name, g.tag);
    if (r.status !== "ok") {
      lines.push(`- ${label}: ${state}; tag lookup failed (${r.status})`);
      continue;
    }
    if (r.digest === g.digest) {
      lines.push(`- ${label}: ${state}; up to date`);
      continue;
    }
    candidates.push({ g, to: r.digest });
  }
  if (!candidates.length) return { bumps: [], files: [], lines };
  const reply = await client.images(IMAGES_REF, [...new Map(candidates.map((c) => [`${c.g.name}@${c.to}`, { name: c.g.name, digest: c.to }])).values()], { mainOnly: true });
  const decision = new Map(reply.images.map((d) => [`${d.name}@${d.digest}`, d]));
  const bumps = [];
  const edited = /* @__PURE__ */ new Map();
  for (const { g, to } of candidates) {
    const label = `\`${safe2(g.name)}:${safe2(g.tag)}\` ${short(g.digest)} \u2192 ${short(to)}`;
    const d = decision.get(`${g.name}@${to}`);
    if (!d || d.decision !== "allow") {
      const why = !d ? "no decision" : d.decision === "blocked" ? "blocked" : d.eligibleAt ? `cooldown until ${d.eligibleAt.slice(0, 10)}` : "not verified yet";
      lines.push(`- ${label}: newer digest waiting (${why})`);
      continue;
    }
    const before = await findings(g.name, g.digest, g.platform);
    const after = await findings(g.name, to, g.platform);
    if (before === null || after === null) {
      lines.push(`- ${label}: scan error; not bumped`);
      continue;
    }
    const fkey = (f) => `${f.id}\0${f.package}`;
    const beforeIds = new Set(before.map(fkey));
    const afterIds = new Set(after.map((f) => f.id));
    const fixes = [...new Map(before.filter((f) => isSerious(f) && !afterIds.has(f.id)).map((f) => [f.id, f])).values()];
    const introduced = [...new Map(after.filter((f) => !beforeIds.has(fkey(f))).map((f) => [fkey(f), f])).values()];
    if (!fixes.length) {
      lines.push(`- ${label}: fixes no High/Critical finding; not bumped`);
      continue;
    }
    const worse = introduced.filter(isSerious);
    if (worse.length) {
      lines.push(`- ${label}: would introduce ${worse.map((f) => `${safe2(f.id)} (${f.severity})`).join(", ")}; not bumped`);
      continue;
    }
    const pending = /* @__PURE__ */ new Map();
    let ok = true;
    for (const u of g.uses) {
      const text = pending.get(u.rel) ?? edited.get(u.rel) ?? texts.get(u.rel);
      const ls = text.split("\n");
      const at = ls.findIndex((l, i) => i >= u.line - 1 && i < u.line + 9 && l.includes(`@${g.digest}`));
      if (at < 0) {
        ok = false;
        break;
      }
      ls[at] = ls[at].replace(`@${g.digest}`, `@${to}`);
      pending.set(u.rel, ls.join("\n"));
    }
    if (!ok) {
      lines.push(`- ${label}: the digest is not written on its FROM line (an ARG?); not bumped`);
      continue;
    }
    for (const [rel, t] of pending) edited.set(rel, t);
    const severity = SEV_ORDER.find((s) => fixes.some((f) => f.severity === s)) ?? "high";
    bumps.push({ name: g.name, tag: g.tag, from: g.digest, to, fixes, introduced, severity, files: [...new Set(g.uses.map((u) => repoPath(join2(wd, u.rel))))] });
    lines.push(`- ${label}: bump fixes ${fixes.map((f) => safe2(f.id)).join(", ")}`);
  }
  const files = [...edited].map(([rel, contents]) => ({ path: repoPath(join2(wd, rel)), contents }));
  return { bumps, files, lines };
}

// action/src/decant-client.ts
function classify404(body) {
  if (/is not available: in cooldown/.test(body)) return "cooldown";
  if (/is not available: blocked/.test(body)) return "blocked";
  return "missing";
}
function npmMetaPath(name) {
  return name.split("/").map((p) => encodeURIComponent(p).replace(/^%40/, "@")).join("%2f");
}
function decant(f, url, token, retry = {}) {
  const base = url.replace(/\/+$/, "");
  const origin = new URL(base).origin;
  const basic = Buffer.from(`decant:${token}`).toString("base64");
  const secrets = [token, basic];
  const bearer = { authorization: `Bearer ${token}` };
  async function call(method, path, opts = {}) {
    const target2 = path.startsWith("https://") || path.startsWith("http://") ? path : `${base}${path}`;
    if (new URL(target2).origin !== origin) throw new Error(`decant: refusing to send credentials to another host (${new URL(target2).host})`);
    const headers = { ...bearer, ...opts.headers };
    let body;
    if (opts.body !== void 0) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    return requestWithRetry(f, target2, { method, headers, body }, {
      label: `decant ${method} ${new URL(target2).pathname}`,
      timeoutMs: TIMEOUT_MS,
      secrets,
      sleep: retry.sleep ?? realSleep,
      random: retry.random,
      now: retry.now,
      retryStatuses: opts.retryStatuses
    });
  }
  async function ok(res, label) {
    if (!res.ok) throw await httpError(res, { label, secrets });
    return readJson(res, label);
  }
  const prefix = (ref) => ref ? `/r/${encodeURIComponent(ref)}` : "";
  async function bytesOr404(res, label) {
    if (res.status === 404 || res.status === 410) return { status: classify404(await res.text().catch(() => "")) };
    if (!res.ok) throw await httpError(res, { label, secrets });
    return { status: "ok", bytes: new Uint8Array(await res.arrayBuffer()) };
  }
  async function npmTarball(name, version, ref) {
    const npmBase = `${base}${prefix(ref)}/npm`;
    const metaLabel = `decant GET ${prefix(ref)}/npm/${name}`;
    const meta = await call("GET", `${npmBase}/${npmMetaPath(name)}`, { headers: { accept: "application/json" } });
    if (meta.status === 404) return { status: classify404(await meta.text().catch(() => "")) };
    const doc = await ok(meta, metaLabel);
    const tarball = doc.versions?.[version]?.dist?.tarball;
    if (typeof tarball === "string") {
      let u;
      try {
        u = new URL(tarball);
      } catch {
        throw new Error(`${metaLabel}: invalid tarball URL`);
      }
      if (u.origin !== origin) throw new Error(`${metaLabel}: tarball host ${u.host} is not the decant host`);
      return { target: u.href, listed: true };
    }
    const basename = name.slice(name.lastIndexOf("/") + 1);
    return { target: `${npmBase}/${name}/-/${basename}-${encodeURIComponent(version)}.tgz`, listed: false };
  }
  return {
    /** PUT the policy for `ref`. Never throws on an HTTP status: the caller reports {status, body}. */
    async syncPolicy(project, policy, sha, ref) {
      const parsed = typeof policy === "string" ? JSON.parse(policy) : policy;
      const res = await call("PUT", `/api/projects/${encodeURIComponent(project)}/policy`, { body: { policy: parsed, sha, ref }, retryStatuses: false });
      const text = await res.text();
      let body = text;
      try {
        body = JSON.parse(text);
      } catch {
      }
      return { status: res.status, body };
    },
    /** PUT the default branch's dependency summary (sync token), with the GitHub repo when known. Never throws on an HTTP status. */
    async syncDeps(project, sha, deps, repo) {
      const payload = repo === void 0 ? { sha, deps } : { sha, deps, repo };
      const res = await call("PUT", `/api/projects/${encodeURIComponent(project)}/deps`, { body: payload, retryStatuses: false });
      const text = await res.text();
      let body = text;
      try {
        body = JSON.parse(text);
      } catch {
      }
      return { status: res.status, body };
    },
    /**
     * Reports image digests for `ref` and returns each one's decision. decant verifies new digests in the
     * registry itself before starting any cooldown clock. A main report (sync token) replaces the images in
     * use, so it is not retried on a gateway error (a late retry could overwrite a newer report).
     */
    async images(ref, images, opts = {}) {
      const body = opts.mainOnly ? { ref, images, mainOnly: true } : { ref, images };
      const res = await call("POST", "/api/images", { body, retryStatuses: !opts.main });
      return ok(res, "decant POST /api/images");
    },
    async getVerdicts(pkgId) {
      const res = await call("GET", `/api/verdicts?package=${encodeURIComponent(pkgId)}`);
      return (await ok(res, "decant GET /api/verdicts")).verdicts ?? [];
    },
    async putVerdict(v) {
      const res = await call("PUT", "/api/verdicts", { body: v });
      if (!res.ok) throw await httpError(res, { label: "decant PUT /api/verdicts", secrets });
    },
    async blocks() {
      return (await ok(await call("GET", "/api/blocks"), "decant GET /api/blocks")).blocks ?? [];
    },
    async status(project) {
      const path = `/api/projects/${encodeURIComponent(project)}/status`;
      return ok(await call("GET", path), `decant GET ${path}`);
    },
    /**
     * Reads `<prefix>/npm/<name>` metadata (filtered by decant for that ref) and fetches the version's
     * dist.tarball. A version filtered out of the metadata is requested at its canonical tarball path
     * so decant's 404 says why (cooldown or blocked).
     */
    async downloadNpm(name, version, ref) {
      const t = await npmTarball(name, version, ref);
      if ("status" in t) return t;
      const res = await call("GET", t.target);
      return bytesOr404(res, `decant GET ${new URL(t.target).pathname}`);
    },
    /**
     * Whether name@version is installable through `ref` now, without downloading it: npm reads the
     * (filtered) metadata, asking the tarball path for the reason only when the version is not listed;
     * Go GETs the gated `.info`.
     */
    async availability(eco, name, version, ref) {
      if (eco === "go") {
        const path = `${prefix(ref)}/go/${escapeModulePath(name)}/@v/${escapeModulePath(version)}.info`;
        const res2 = await call("GET", path, { headers: { authorization: `Basic ${basic}` } });
        const d = await bytesOr404(res2, `decant GET ${path}`);
        return d.status;
      }
      const t = await npmTarball(name, version, ref);
      if ("status" in t) return t.status;
      if (t.listed) return "ok";
      const res = await call("GET", t.target);
      if (res.status === 404 || res.status === 410) return classify404(await res.text().catch(() => ""));
      if (!res.ok) throw await httpError(res, { label: `decant GET ${new URL(t.target).pathname}`, secrets });
      await res.body?.cancel().catch(() => {
      });
      return "ok";
    },
    /** Fetches `<prefix>/go/<module>/@v/<version>.zip` with Basic decant:<token>. */
    async downloadGo(module, version, ref) {
      const path = `${prefix(ref)}/go/${escapeModulePath(module)}/@v/${escapeModulePath(version)}.zip`;
      const res = await call("GET", path, { headers: { authorization: `Basic ${basic}` } });
      return bytesOr404(res, `decant GET ${path}`);
    }
  };
}

// src/vuln-severity.ts
var GHSA_SEVERITY = { CRITICAL: "critical", HIGH: "high", MODERATE: "moderate", MEDIUM: "moderate", LOW: "low" };
var RANK2 = { unknown: 0, low: 1, moderate: 2, high: 3, critical: 4 };
function maxSeverity(...s) {
  return s.reduce((a, b) => RANK2[b] > RANK2[a] ? b : a, "unknown");
}
var CVSS_W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 }
};
function roundup(x) {
  const i = Math.round(x * 1e5);
  return i % 1e4 === 0 ? i / 1e5 : (Math.floor(i / 1e4) + 1) / 10;
}
function cvss31BaseScore(vector) {
  const parts = vector.split("/");
  if (parts[0] !== "CVSS:3.1" && parts[0] !== "CVSS:3.0") return null;
  const m = {};
  for (const p of parts.slice(1)) {
    const [k, v] = p.split(":");
    if (k && v) m[k] = v;
  }
  const S = m.S;
  if (S !== "U" && S !== "C") return null;
  const av = CVSS_W.AV[m.AV];
  const ac = CVSS_W.AC[m.AC];
  const ui = CVSS_W.UI[m.UI];
  const pr = { N: 0.85, L: S === "C" ? 0.68 : 0.62, H: S === "C" ? 0.5 : 0.27 }[m.PR];
  const [c, i, a] = [m.C, m.I, m.A].map((x) => CVSS_W.CIA[x]);
  if ([av, ac, ui, pr, c, i, a].some((x) => x === void 0)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = S === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return roundup(Math.min((S === "U" ? 1 : 1.08) * (impact + expl), 10));
}
function scoreSeverity(score) {
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "moderate" : score > 0 ? "low" : "unknown";
}
function severityOf(r) {
  const sev = r.database_specific?.severity;
  const db = typeof sev === "string" ? GHSA_SEVERITY[sev.toUpperCase()] ?? "unknown" : "unknown";
  const cvss = (r.severity ?? []).filter((x) => x.type === "CVSS_V3" && typeof x.score === "string").map((x) => cvss31BaseScore(x.score)).map((n) => n === null ? "unknown" : scoreSeverity(n));
  return maxSeverity(db, ...cvss);
}

// action/src/osv.ts
var OSV = "https://api.osv.dev";
var OSV_ECO = { npm: "npm", go: "Go", docker: "" };
var BATCH = 1e3;
var MAX_PAGES2 = 10;
var DETAIL_CONCURRENCY = 8;
function depKey(d) {
  return `${d.eco}:${d.name}@${d.version}`;
}
var withV = (eco, v) => eco === "go" && !v.startsWith("v") ? `v${v}` : v;
function rangeCover(events, eco, version) {
  const cmp = (a, b) => compareVersions(a, b, eco);
  const pos = (e) => {
    const raw = e.introduced ?? e.fixed ?? e.last_affected ?? e.limit;
    if (raw === void 0) return null;
    return raw === "0" && e.introduced !== void 0 ? null : withV(eco, raw);
  };
  const sorted = [...events].sort((a, b) => {
    const pa = pos(a);
    const pb = pos(b);
    if (pa === null || pb === null) return pa === pb ? 0 : pa === null ? -1 : 1;
    return cmp(pa, pb);
  });
  let start;
  let best = { covered: false };
  const inside = (lo) => lo === null || cmp(version, lo) >= 0;
  for (const e of sorted) {
    if (e.introduced !== void 0) {
      if (start === void 0) start = e.introduced === "0" ? null : withV(eco, e.introduced);
      continue;
    }
    if (start === void 0) continue;
    if (e.fixed !== void 0 || e.limit !== void 0) {
      const end = withV(eco, e.fixed ?? e.limit);
      if (e.fixed !== void 0 && parseVersion(end, eco) === null) {
        if (inside(start)) return { covered: true, fixed: end };
        start = void 0;
        continue;
      }
      if (inside(start) && cmp(version, end) < 0) {
        if (e.fixed !== void 0) return { covered: true, fixed: end };
        best = { covered: true, fixed: null };
      }
      start = void 0;
    } else if (e.last_affected !== void 0) {
      if (inside(start) && cmp(version, withV(eco, e.last_affected)) <= 0) best = { covered: true, fixed: null };
      start = void 0;
    }
  }
  if (start !== void 0 && inside(start)) best = { covered: true, fixed: null };
  return best;
}
function toVuln(r) {
  const entries = (eco, name) => (r.affected ?? []).filter((a) => a.package?.ecosystem === OSV_ECO[eco] && a.package?.name === name);
  function cover(eco, name, version) {
    let covered = false;
    const parsable = parseVersion(version, eco) !== null;
    for (const a of entries(eco, name)) {
      for (const rg of parsable ? a.ranges ?? [] : []) {
        if (rg.type !== "SEMVER" && rg.type !== "ECOSYSTEM") continue;
        const c = rangeCover(rg.events ?? [], eco, version);
        if (c.covered && c.fixed !== null) return c;
        covered ||= c.covered;
      }
      if ((a.versions ?? []).some((v) => withV(eco, v) === version)) covered = true;
    }
    return covered ? { covered: true, fixed: null } : { covered: false };
  }
  return {
    id: r.id,
    aliases: r.aliases ?? [],
    severity: severityOf(r),
    summary: r.summary ?? r.details?.split("\n")[0] ?? "",
    malicious: r.id.startsWith("MAL-"),
    fixedFor(eco, name, version) {
      const c = cover(eco, name, version);
      return c.covered ? c.fixed : null;
    },
    affects: (eco, name, version) => cover(eco, name, version).covered
  };
}
function mergeAliases(vulns) {
  const parent = vulns.map((_, i) => i);
  const find = (i) => parent[i] === i ? i : parent[i] = find(parent[i]);
  const owner = /* @__PURE__ */ new Map();
  vulns.forEach((v, i) => {
    for (const name of [v.id, ...v.aliases]) {
      const j = owner.get(name);
      if (j === void 0) owner.set(name, i);
      else parent[find(i)] = find(j);
    }
  });
  const groups = /* @__PURE__ */ new Map();
  vulns.forEach((v, i) => {
    const g = groups.get(find(i)) ?? [];
    g.push(v);
    groups.set(find(i), g);
  });
  return [...groups.values()].map((g) => {
    if (g.length === 1) return g[0];
    const primary = g.find((v) => v.id.startsWith("GHSA-")) ?? g[0];
    const names = new Set(g.flatMap((v) => [v.id, ...v.aliases]));
    names.delete(primary.id);
    return {
      id: primary.id,
      aliases: [...names],
      severity: maxSeverity(...g.map((v) => v.severity)),
      summary: primary.summary || (g.find((v) => v.summary)?.summary ?? ""),
      malicious: g.some((v) => v.malicious),
      // Highest fix across the group: a lower one would leave another member's advisory open.
      fixedFor: (eco, name, version) => {
        let best = null;
        for (const v of g) {
          const x = v.fixedFor(eco, name, version);
          if (x !== null && (best === null || compareVersions(x, best, eco) > 0)) best = x;
        }
        return best;
      },
      affects: (eco, name, version) => g.some((v) => v.affects(eco, name, version))
    };
  });
}
function createOsv(f) {
  const details = /* @__PURE__ */ new Map();
  async function post(path, body) {
    const label = `OSV POST ${path}`;
    const res = await request(
      f,
      `${OSV}${path}`,
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
      { label, timeoutMs: OSV_TIMEOUT_MS }
    );
    if (!res.ok) throw await httpError(res, { label });
    return readJson(res, label);
  }
  function vuln(id) {
    let p = details.get(id);
    if (!p) {
      const label = `OSV GET /v1/vulns/${id}`;
      p = (async () => {
        const res = await request(f, `${OSV}/v1/vulns/${encodeURIComponent(id)}`, {}, { label, timeoutMs: OSV_TIMEOUT_MS });
        if (res.status === 404) return null;
        if (!res.ok) throw await httpError(res, { label });
        return toVuln(await readJson(res, label));
      })();
      p.catch(() => details.delete(id));
      details.set(id, p);
    }
    return p;
  }
  async function queryVulns(deps) {
    const unique = /* @__PURE__ */ new Map();
    for (const d of deps) unique.set(depKey(d), d);
    const keys = [...unique.keys()];
    const ids = new Map(keys.map((k) => [k, /* @__PURE__ */ new Set()]));
    for (let i = 0; i < keys.length; i += BATCH) {
      let pending = keys.slice(i, i + BATCH).map((k) => {
        const d = unique.get(k);
        const q = { package: { ecosystem: OSV_ECO[d.eco], name: d.name }, version: d.eco === "go" ? d.version.replace(/^v/, "") : d.version };
        return { k, q };
      });
      for (let page = 0; pending.length > 0; page++) {
        if (page >= MAX_PAGES2) throw new Error(`OSV: more than ${MAX_PAGES2} pages of results`);
        const r = await post("/v1/querybatch", { queries: pending.map((p) => p.q) });
        if (!Array.isArray(r.results) || r.results.length < pending.length) {
          throw new Error(`OSV POST /v1/querybatch: expected ${pending.length} results, got ${Array.isArray(r.results) ? r.results.length : "none"}`);
        }
        const next = [];
        pending.forEach((p, j) => {
          const res = r.results?.[j];
          for (const v of res?.vulns ?? []) ids.get(p.k).add(v.id);
          if (res?.next_page_token) next.push({ k: p.k, q: { ...p.q, page_token: res.next_page_token } });
        });
        pending = next;
      }
    }
    const all = [...new Set([...ids.values()].flatMap((s) => [...s]))];
    for (let i = 0; i < all.length; i += DETAIL_CONCURRENCY) await Promise.all(all.slice(i, i + DETAIL_CONCURRENCY).map(vuln));
    const resolved = /* @__PURE__ */ new Map();
    for (const id of all) {
      const v = await vuln(id);
      if (!v) continue;
      const ghsa = v.aliases.filter((a) => a.startsWith("GHSA-") && a !== v.id);
      const alts = await Promise.all(ghsa.map((a) => vuln(a)));
      const severity = maxSeverity(v.severity, ...alts.map((a) => a?.severity ?? "unknown"));
      resolved.set(id, severity === v.severity ? v : { ...v, severity });
    }
    const out = /* @__PURE__ */ new Map();
    for (const [k, s] of ids) {
      out.set(k, mergeAliases([...s].flatMap((id) => resolved.get(id) ?? [])));
    }
    return out;
  }
  return { queryVulns, vuln };
}

// action/src/modes/audit.ts
var DAY2 = 864e5;
var FIX_BRANCH = "decant/security-fixes";
var OVERLAY_REF = "audit";
var PRUNE_BRANCH = "decant/prune";
var UNFIXED_TITLE = "decant: unfixed advisories";
var BLOCKED_TITLE = "decant: blocked versions in lockfiles";
var ISSUE_LABELS = ["decant:security"];
var SET_MARKER = /<!-- decant-audit-set: ([0-9a-f]{64}) -->/;
var NPM_NAME = /^(?:@[A-Za-z0-9~][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~][A-Za-z0-9._~-]*$/;
var GO_MODULE = /^[A-Za-z0-9][A-Za-z0-9._~+/-]*$/;
var safe3 = (s) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, "?");
var cell = (s, n = 200) => s.replace(/\s+/g, " ").replace(/[|<>]/g, " ").slice(0, n);
var ymd2 = (d) => d.toISOString().slice(0, 10);
var isPackageLock = (rel) => rel === "package-lock.json" || rel.endsWith("/package-lock.json");
var plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
function line(v, eco) {
  const p = parseVersion(v, eco);
  if (!p) return `?${v}`;
  return p.major > 0 ? String(p.major) : `0.${p.minor}`;
}
function overrideKey(name, version) {
  const p = parseVersion(version, "npm");
  if (!p) throw new PkgError("unresolvable", `cannot build an override for ${safe3(name)}@${safe3(version)}`);
  return p.major > 0 ? `${name}@^${p.major}` : `${name}@~0.${p.minor}`;
}
function auditSetHash(ids) {
  return createHash2("sha256").update([...ids].sort().join("\n")).digest("hex");
}
var markerOf = (body) => SET_MARKER.exec(body)?.[1] ?? null;
function advisoryUrl(id) {
  return id.startsWith("GHSA-") ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}
var systemic = (e) => /^(GitHub|decant) [A-Z]+ \S+: HTTP 40[13]\b/.test(e?.message ?? "");
var sevOf = (v) => v.severity === "unknown" ? "moderate" : v.severity;
var sevRank = (s) => SEVERITIES.indexOf(s);
var maxSev = (ss) => ss.reduce((a, b) => sevRank(b) < sevRank(a) ? b : a, "low");
var bySeverity = (a, b) => sevRank(sevOf(a)) - sevRank(sevOf(b)) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
var FatalError = class extends Error {
};
var PkgError = class extends Error {
  constructor(result, msg) {
    super(msg);
    this.result = result;
  }
  result;
};
var uniqSorted = (vs, eco) => [...new Set(vs)].sort((a, b) => compareVersions(a, b, eco));
var targetsOf = (p) => uniqSorted(p.copies.map((c) => c.target), p.eco);
var oldsOf = (p) => uniqSorted(p.copies.map((c) => c.dep.version), p.eco);
var idsOf = (p) => targetsOf(p).map((t) => formatPackageId({ eco: p.eco, name: p.name, version: t }));
var imageIds = (bs) => bs.map((b) => formatPackageId({ eco: "docker", name: b.name, version: b.to }));
function validFix(v, eco, name, version) {
  const f = v.fixedFor(eco, name, version);
  return f !== null && parseVersion(f, eco) !== null ? f : null;
}
function targetFor(vulns, eco, name, version) {
  let t = version;
  for (let i = 0; i < 16; i++) {
    let next = null;
    for (const v of vulns) {
      const f = validFix(v, eco, name, t);
      if (f !== null && compareVersions(f, t, eco) > 0 && (next === null || compareVersions(f, next, eco) > 0)) next = f;
    }
    if (next === null) break;
    t = next;
  }
  return t === version ? null : t;
}
var stillVulnerable = (p, version) => p.vulns.some((v) => validFix(v, p.eco, p.name, version) !== null);
async function run2({ deps, inputs }) {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.syncToken);
  mask(inputs.githubToken);
  const stop = (msg) => {
    setOutput("result", "fail", env);
    error(msg);
    process.stderr.write(`${msg}
`);
    return 1;
  };
  if (!inputs.githubToken) return stop("github-token is required");
  if (!inputs.token) return stop("token is required (ci token)");
  if (!inputs.syncToken) return stop("sync-token is required: decant reserves the audit overlay ref for the sync token (see docs/release.md)");
  if (!inputs.decantUrl) return stop("decant-url is required");
  if (!env.RUNNER_TEMP) return stop("RUNNER_TEMP is not set; decant audit runs on GitHub Actions runners");
  const repo = env.GITHUB_REPOSITORY ?? "";
  const wd = inputs.workingDirectory;
  const policyAbs = join3(wd, inputs.policyPath);
  const root = env.GITHUB_WORKSPACE || (isAbsolute2(wd) ? wd : process.cwd());
  const repoPath = (abs) => relative2(resolve2(root), resolve2(root, abs)).split("\\").join("/");
  const policyRel = repoPath(policyAbs);
  if (policyRel.startsWith("..")) return stop(`${policyAbs} is outside the repository`);
  if (!await deps.fs.exists(policyAbs)) return stop(`decant.json not found at ${policyAbs}`);
  let raw;
  try {
    raw = JSON.parse(await deps.fs.readFile(policyAbs));
  } catch (e) {
    return stop(`${policyAbs} is not valid JSON: ${e.message}`);
  }
  const parsed = parsePolicy(raw);
  if (!parsed.ok) return stop(`invalid policy:
${parsed.errors.map((m) => `- ${m}`).join("\n")}`);
  const policy = parsed.policy;
  const project = inputs.project || policy.project;
  const tree = await findLockfileTree(wd, deps.fs);
  if (tree.symlinks.length) {
    for (const l of tree.symlinks) {
      const msg = `${join3(wd, l.path)}: ${l.dir ? "symlinked directory" : "lockfile is a symlink"}; not supported`;
      error(msg);
      process.stderr.write(`${msg}
`);
    }
    return stop(`${tree.symlinks.length} symlink(s) in ${wd}; decant does not audit through symlinks`);
  }
  const all = [];
  for (const rel of tree.files) {
    const abs = join3(wd, rel);
    try {
      const text = await deps.fs.readFile(abs);
      all.push(...isPackageLock(rel) ? parsePackageLock(text, rel, inputs.decantUrl) : parseGoSum(text, rel));
    } catch (e) {
      return stop(`${abs}: ${e.message}`);
    }
  }
  const registry = all.filter((d) => d.source === "registry" && d.version);
  const now = deps.now();
  const today = ymd2(now);
  const outcomes = [];
  const lines = [];
  let tmp = null;
  let fatal = null;
  try {
    const gh = github(deps.fetch, inputs.githubToken, repo, { selfLogin: env.DECANT_GITHUB_LOGIN || void 0 });
    const co = await defaultHeadCheckout(gh, env, "audit");
    if (!co.ok) return stop(co.message);
    const vulnsByKey = registry.length ? await createOsv(deps.fetch).queryVulns(registry) : /* @__PURE__ */ new Map();
    const byPkg = /* @__PURE__ */ new Map();
    const unfixed = [];
    for (const d of registry) {
      for (const v of vulnsByKey.get(depKey(d)) ?? []) {
        const rawFix = v.fixedFor(d.eco, d.name, d.version);
        if (validFix(v, d.eco, d.name, d.version) === null) {
          unfixed.push({ vuln: v, dep: d, reason: rawFix === null ? "no fixed version" : "invalid fixed version" });
          continue;
        }
        const k = `${d.eco}:${d.name}`;
        const g = byPkg.get(k) ?? { eco: d.eco, name: d.name, copies: /* @__PURE__ */ new Map() };
        byPkg.set(k, g);
        g.copies.set(d, [...g.copies.get(d) ?? [], v]);
      }
    }
    const pkgs = [];
    for (const [, g] of [...byPkg].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
      const vulns = [...new Map([...g.copies.values()].flat().map((v) => [v.id, v])).values()].sort(bySeverity);
      const copies = [...g.copies].map(([dep, vs]) => ({ dep, vulns: vs, target: targetFor(vulns, g.eco, g.name, dep.version) }));
      const p = { eco: g.eco, name: g.name, copies, vulns };
      if (!(g.eco === "npm" ? NPM_NAME : GO_MODULE).test(g.name) || g.name.includes("..")) {
        outcomes.push({ pkg: p, result: "failed", detail: `invalid package name ${safe3(g.name)}` });
      } else pkgs.push(p);
    }
    const client = decant(deps.fetch, inputs.decantUrl, inputs.token, { sleep: deps.sleep });
    const ctx = {
      deps,
      inputs,
      gh,
      client,
      // The overlay ref `audit` is reserved for the sync token on the Worker: no ci token can write it.
      overlayClient: inputs.syncToken ? decant(deps.fetch, inputs.decantUrl, inputs.syncToken, { sleep: deps.sleep }) : null,
      raw,
      policy,
      project,
      today,
      wd,
      repoPath,
      policyRel,
      base: co.base,
      sha: co.sha,
      tmpFile: async (ext) => `${await (tmp ??= deps.fs.mkdtemp(`${env.RUNNER_TEMP}/decant-audit-`))}/${randomUUID2()}.${ext}`
    };
    let images = { bumps: [], files: [], lines: [] };
    try {
      images = await auditImages(deps, client, wd, repoPath);
    } catch (e) {
      if (systemic(e)) throw e;
      const msg = redact(e.message, [inputs.token, inputs.githubToken]);
      images.lines.push(`- image audit failed: ${cell(msg)}`);
      warning(`image audit failed: ${msg}`);
    }
    const bumps = images.bumps;
    let prLine = "no fixable advisories";
    if (pkgs.length || bumps.length) {
      try {
        const lookup = async (what, f) => {
          try {
            return await f();
          } catch (e) {
            if (systemic(e)) throw e;
            throw new FatalError(`looking up the ${what} security PR: ${e.message}`);
          }
        };
        const open = await lookup("open", () => gh.findOpenPr(FIX_BRANCH));
        const closed = open ? null : await lookup("closed", () => gh.findClosedUnmergedPr(FIX_BRANCH));
        const declined = (set) => closed !== null && markerOf(closed.body) === auditSetHash([...set.flatMap(idsOf), ...imageIds(bumps)]);
        if (declined(pkgs)) {
          prLine = `declined (#${closed.number} closed without merging the same fixes)`;
          for (const p of pkgs) outcomes.push({ pkg: p, result: "declined", detail: `PR #${closed.number}` });
        } else {
          const batch = pkgs.length ? await syncOverlay(ctx, pkgs, outcomes) : [];
          const locked = new Set(all.filter((d) => d.version).map(formatPackageId));
          const { fixed, files } = batch.length ? await applyAll(ctx, batch, outcomes, locked) : { fixed: [], files: [] };
          if (!fixed.length && !bumps.length) prLine = "nothing to ship";
          else if (!open && declined(fixed)) prLine = `declined (#${closed.number} closed without merging the same fixes)`;
          else {
            if (batch.length) strayOverlayVersions(ctx, batch, fixed, files, locked);
            prLine = await publish(ctx, fixed, [...files, ...images.files], open, outcomes, unfixed, bumps);
          }
        }
      } catch (e) {
        if (systemic(e)) throw e;
        const msg = redact(e.message, [inputs.token, inputs.githubToken]);
        prLine = `failed: ${msg}`;
        if (e instanceof FatalError) fatal = msg;
        else warning(`security PR ${prLine}`);
      }
    }
    for (const o of outcomes) {
      if (o.result === "fixed" || o.result === "declined") continue;
      for (const c of o.pkg.copies) for (const v of c.vulns) unfixed.push({ vuln: v, dep: c.dep, reason: `${o.result}: ${cell(o.detail, 120)}` });
    }
    const unfixedIssue = await syncIssue(gh, UNFIXED_TITLE, unfixed.length ? unfixedBody(unfixed) : null);
    const blocks = await client.blocks();
    const byId = /* @__PURE__ */ new Map();
    for (const d of all) {
      if (!d.version) continue;
      const id = formatPackageId(d);
      byId.set(id, [...byId.get(id) ?? [], d]);
    }
    const hits = blocks.filter((b) => byId.has(b.package));
    const blockedIssue = await syncIssue(gh, BLOCKED_TITLE, hits.length ? blockedBody(hits.map((b) => ({ ...b, files: [...new Set(byId.get(b.package).map((d) => d.file))] }))) : null);
    let prune;
    try {
      prune = await pruneAllow(ctx, now);
    } catch (e) {
      if (systemic(e)) throw e;
      prune = `failed: ${redact(e.message, [inputs.token, inputs.githubToken])}`;
      warning(`prune ${prune}`);
    }
    lines.push("## decant audit", "");
    if (outcomes.length) {
      lines.push("| Package | Upgrade | Advisories | Result |", "|---|---|---|---|");
      for (const o of outcomes) {
        const detail = o.detail.replace(/\s+/g, " ").replace(/\|/g, "\\|").slice(0, 200);
        lines.push(
          `| \`${safe3(o.pkg.name)}\` | ${oldsOf(o.pkg).map(safe3).join(", ")} \u2192 ${targetsOf(o.pkg).map(safe3).join(", ")} | ${o.pkg.vulns.map((v) => safe3(v.id)).join(", ")} | ${o.result}${detail ? `: ${detail}` : ""} |`
        );
      }
    } else lines.push("No fixable advisories.");
    if (images.lines.length) lines.push("", "### Base images", "", ...images.lines);
    const count2 = (r) => outcomes.filter((o) => o.result === r).length;
    lines.push(
      "",
      `Security PR: ${prLine}`,
      `Packages fixed: ${count2("fixed")} \xB7 declined: ${count2("declined")} \xB7 unverified: ${count2("unverified")} \xB7 unresolvable: ${count2("unresolvable")} \xB7 failed: ${count2("failed")}`,
      `Unfixed advisories: ${unfixed.length}${unfixedIssue ? ` (issue #${unfixedIssue})` : ""}`,
      `Blocked versions in lockfiles: ${hits.length}${blockedIssue ? ` (issue #${blockedIssue})` : ""}`,
      `Prune: ${prune}`
    );
  } catch (e) {
    return stop(`decant audit: ${redact(e.message, [inputs.token, inputs.githubToken])}`);
  } finally {
    if (tmp) await deps.fs.rm(await tmp.catch(() => "")).catch(() => {
    });
  }
  appendSummary(lines.join("\n"), env);
  if (fatal !== null) return stop(`decant audit: ${fatal}`);
  setOutput("result", "pass", env);
  return 0;
}
var mainAllow = (ctx) => ctx.raw.allow ?? [];
function allowEntries(ctx, p) {
  const have = new Set(mainAllow(ctx).map((a) => a.package));
  const out = [];
  for (const t of targetsOf(p)) {
    const pkgId = formatPackageId({ eco: p.eco, name: p.name, version: t });
    if (have.has(pkgId)) continue;
    const vs = [...new Map(p.copies.filter((c) => c.target === t).flatMap((c) => c.vulns).map((v) => [v.id, v])).values()].sort(bySeverity);
    const rest = vs.slice(1).map((v) => v.id).sort();
    out.push({ package: pkgId, advisory: vs[0].id, reason: rest.length ? `security fix: ${rest.join(", ")}` : "security fix", added: ctx.today });
  }
  return out;
}
var errorText = (b) => (typeof b === "object" && b && typeof b.error === "string" ? b.error : typeof b === "string" ? b : JSON.stringify(b)).slice(0, 300);
async function syncOverlay(ctx, pkgs, outcomes) {
  let batch = [];
  for (const p of pkgs) {
    const check = parsePolicy({ ...ctx.raw, allow: [...mainAllow(ctx), ...allowEntries(ctx, p)] });
    if (check.ok) batch.push(p);
    else outcomes.push({ pkg: p, result: "failed", detail: `allow entry invalid: ${check.errors.join("; ")}` });
  }
  for (let attempt = 0; batch.length; attempt++) {
    const next = { ...ctx.raw, allow: [...mainAllow(ctx), ...batch.flatMap((p) => allowEntries(ctx, p))] };
    const check = parsePolicy(next);
    if (!check.ok) throw new FatalError(`overlay policy invalid: ${check.errors.join("; ")}`);
    if (!ctx.overlayClient) throw new FatalError(`sync-token is required to ship fixes: decant reserves the overlay ref ${OVERLAY_REF} for the sync token`);
    const res = await ctx.overlayClient.syncPolicy(ctx.project, next, ctx.sha, OVERLAY_REF);
    if (res.status === 401 || res.status === 403) throw new Error(`decant PUT /api/projects/${ctx.project}/policy: HTTP ${res.status}`);
    if (res.status >= 200 && res.status < 300) return batch;
    const failure2 = `overlay sync HTTP ${res.status}: ${errorText(res.body)}`;
    const named = res.body?.entries;
    const rejected = Array.isArray(named) ? named.filter((e) => typeof e === "string") : [];
    const why = (p) => rejected.filter((e) => idsOf(p).includes(e.split(" ")[0]));
    const drop = batch.filter((p) => why(p).length);
    if (attempt > 0 || !drop.length) throw new FatalError(failure2);
    for (const p of drop) outcomes.push({ pkg: p, result: "unverified", detail: `not verified by decant: ${why(p).join("; ")}` });
    batch = batch.filter((p) => !drop.includes(p));
  }
  return batch;
}
async function applyAll(ctx, pkgs, outcomes, locked) {
  const overlayOnly = new Set(pkgs.flatMap((p) => allowEntries(ctx, p)).map((a) => a.package).filter((id) => !locked.has(id)));
  const { deps, inputs } = ctx;
  const read = async (abs) => await deps.fs.exists(abs) ? await deps.fs.readFile(abs) : null;
  const put = async (abs, v) => v === null ? deps.fs.rm(abs) : deps.fs.writeFile(abs, v);
  const orig = /* @__PURE__ */ new Map();
  const done = [];
  const files = [];
  try {
    for (const p of pkgs) {
      const before = /* @__PURE__ */ new Map();
      const track = async (abs) => {
        const cur = await read(abs);
        if (!orig.has(abs)) orig.set(abs, cur);
        if (!before.has(abs)) before.set(abs, cur);
      };
      const dirs = [...new Set(p.copies.map((c) => dirname(join3(ctx.wd, c.dep.file))))].sort();
      try {
        for (const dir of dirs) {
          if (p.eco === "npm") await fixNpm(ctx, p, dir, track);
          else await fixGo(ctx, p, dir, track);
        }
        let changed = false;
        for (const [abs, b] of before) if (await read(abs) !== b) changed = true;
        if (!changed) throw new PkgError("unresolvable", "no lockfile changes");
        for (const d of done) {
          const left = [];
          for (const dir of d.dirs) left.push(...await remaining(ctx, d.p, dir));
          if (left.length) throw new PkgError("unresolvable", `would regress ${safe3(d.p.name)}: ${left.join("; ")}`);
        }
        const ok = /* @__PURE__ */ new Set([...idsOf(p), ...done.flatMap((d) => idsOf(d.p))]);
        for (const abs of before.keys()) {
          const text = await read(abs);
          if (text === null) continue;
          const rel = ctx.repoPath(abs);
          const deps2 = isPackageLock(rel) ? parsePackageLock(text, rel, ctx.inputs.decantUrl) : rel === "go.sum" || rel.endsWith("/go.sum") ? parseGoSum(text, rel) : [];
          const stray = deps2.map((d) => formatPackageId(d)).find((id) => overlayOnly.has(id) && !ok.has(id));
          if (stray) throw new PkgError("unresolvable", `pulls in overlay-only ${safe3(stray)}`);
        }
        const o = { pkg: p, result: "fixed", detail: "" };
        outcomes.push(o);
        done.push({ p, o, dirs });
      } catch (e) {
        if (systemic(e)) throw e;
        for (const [abs, b] of before) await put(abs, b);
        const msg = redact(e.message, [inputs.token, inputs.githubToken]);
        const result = e instanceof PkgError ? e.result : "failed";
        if (result === "failed") warning(`${safe3(p.name)}: ${msg}`);
        outcomes.push({ pkg: p, result, detail: msg });
      }
    }
    for (const [abs, b] of orig) {
      const after = await read(abs);
      if (after !== null && after !== b) files.push({ path: ctx.repoPath(abs), contents: after });
    }
  } finally {
    for (const [abs, b] of orig) await put(abs, b);
  }
  return { fixed: done.map((d) => d.p), files };
}
function strayOverlayVersions(ctx, overlay, fixed, files, locked) {
  const shipped = new Set(fixed.flatMap((p) => allowEntries(ctx, p)).map((a) => a.package));
  const stray = new Set(overlay.flatMap((p) => allowEntries(ctx, p)).map((a) => a.package).filter((id) => !shipped.has(id) && !locked.has(id)));
  if (!stray.size) return;
  const hits = /* @__PURE__ */ new Set();
  for (const f of files) {
    const deps = isPackageLock(f.path) ? parsePackageLock(f.contents, f.path, ctx.inputs.decantUrl) : /(^|\/)go\.sum$/.test(f.path) ? parseGoSum(f.contents, f.path) : [];
    for (const d of deps) if (d.version && stray.has(formatPackageId(d))) hits.add(`${safe3(formatPackageId(d))} in ${safe3(f.path)}`);
  }
  if (hits.size) throw new FatalError(`lockfiles would contain overlay-only versions with no allow entry in this PR: ${[...hits].sort().join(", ")}`);
}
async function remaining(ctx, p, dir) {
  if (p.eco === "npm") {
    const left2 = await stale(ctx, `${dir}/package-lock.json`, p);
    return left2.length ? [`${ctx.repoPath(`${dir}/package-lock.json`)} still locks ${uniqSorted(left2.map((c) => c.dep.version), "npm").map(safe3).join(", ")}`] : [];
  }
  const sumAbs = `${dir}/go.sum`;
  const left = parseGoSum(await ctx.deps.fs.readFile(sumAbs), sumAbs).filter((d) => d.name === p.name && stillVulnerable(p, d.version));
  return left.length ? [`${ctx.repoPath(sumAbs)} still has ${left.map((d) => safe3(d.version)).join(", ")}`] : [];
}
async function reusable(ctx, open, files, hash) {
  const { gh } = ctx;
  if (markerOf(open.body) !== hash || open.baseRef !== ctx.base) return false;
  if (!gh.isMine({ login: open.author, type: open.authorType })) return false;
  const changed = await gh.ownSingleCommit(ctx.sha, open.headSha);
  if (changed === null) return false;
  const want = files.map((f) => f.path).sort();
  if (changed.length !== want.length || [...changed].sort().some((p, i) => p !== want[i])) return false;
  for (const f of files) if (await gh.fileAt(f.path, open.headSha) !== f.contents) return false;
  return true;
}
async function publish(ctx, fixed, changed, open, outcomes, unfixed, bumps = []) {
  const { gh } = ctx;
  const ids = [...fixed.flatMap(idsOf), ...imageIds(bumps)];
  const hash = auditSetHash(ids);
  const added = fixed.flatMap((p) => allowEntries(ctx, p));
  const files = [...changed];
  if (added.length) {
    const policy = { ...ctx.raw, allow: [...mainAllow(ctx), ...added] };
    const check = parsePolicy(policy);
    if (!check.ok) throw new FatalError(`decant.json for the PR is invalid: ${check.errors.join("; ")}`);
    files.push({ path: ctx.policyRel, contents: `${JSON.stringify(policy, null, 2)}
` });
  }
  const vulns = [...new Map(fixed.flatMap((p) => p.vulns).map((v) => [v.id, v])).values()];
  const imageVulns = new Set(bumps.flatMap((b) => b.fixes.map((f) => f.id)).filter((id) => !vulns.some((v) => v.id === id || v.aliases.includes(id))));
  const scope = [fixed.length ? plural(fixed.length, "package", "packages") : "", bumps.length ? plural(bumps.length, "image", "images") : ""].filter(Boolean).join(", ");
  const title = `decant: security fixes (${scope}, ${plural(vulns.length + imageVulns.size, "advisory", "advisories")})`;
  const sevOfFinding = (s) => s === "critical" || s === "high" || s === "moderate" || s === "low" ? s : "moderate";
  const sevs = [...vulns.map(sevOf), ...bumps.map((b) => b.severity), ...bumps.flatMap((b) => b.introduced.map((f) => sevOfFinding(f.severity)))];
  const sev = maxSev(sevs);
  const majors = fixed.filter((p) => p.copies.some((c) => line(c.dep.version, p.eco) !== line(c.target, p.eco)));
  const approve = SEVERITIES.filter((s) => sevs.includes(s) && ctx.policy.autoShip[s] !== "auto");
  const auto = !majors.length && !approve.length;
  const left = outcomes.filter((o) => o.result !== "fixed" && o.result !== "declined");
  const body = prBody2({ fixed, added, left, unfixed, auto, majors, approve, cooldownDays: ctx.policy.cooldownDays, paths: files.map((f) => f.path), hash, bumps });
  const labels = ["decant:security", `decant:${sev}`];
  let pr;
  let what;
  let wrote = true;
  if (open) {
    if (!auto && open.autoMerge) {
      try {
        await gh.disableAutoMerge(open.nodeId);
      } catch (e) {
        throw new FatalError(`#${open.number}: could not disable auto-merge, so the branch was not updated: ${e.message}`);
      }
    }
    const same = await reusable(ctx, open, files, hash);
    if (!same) {
      await gh.updateRef(FIX_BRANCH, ctx.sha);
      await gh.commitFiles(FIX_BRANCH, ctx.sha, title, files);
    }
    wrote = !same;
    await gh.updatePr(open.number, { title, body });
    await gh.addLabels(open.number, labels);
    for (const l of open.labels) if (/^decant:(critical|high|moderate|low)$/.test(l) && l !== labels[1]) await gh.removeLabel(open.number, l);
    pr = { number: open.number, nodeId: open.nodeId, url: `#${open.number}` };
    what = same ? `#${open.number} up to date` : `updated #${open.number}`;
    if (!auto && open.autoMerge) what += " (auto-merge turned off)";
    if (auto && open.autoMerge) wrote = false;
  } else {
    try {
      await gh.createBranch(FIX_BRANCH, ctx.sha);
    } catch (e) {
      if (!/HTTP 422/.test(e.message)) throw e;
      await gh.updateRef(FIX_BRANCH, ctx.sha);
    }
    await gh.commitFiles(FIX_BRANCH, ctx.sha, title, files);
    pr = await gh.openPr({ head: FIX_BRANCH, base: ctx.base, title, body, labels });
    what = `opened #${pr.number}`;
  }
  if (auto && wrote) {
    try {
      await gh.enableAutoMerge(pr.nodeId, "SQUASH");
      what += " (auto-merge)";
    } catch (e) {
      warning(`${pr.url}: could not enable auto-merge: ${e.message}`);
      what += " (auto-merge unavailable)";
    }
  } else if (!auto) what += majors.length ? " (major upgrade: auto-merge disabled)" : " (needs approval)";
  notice(`${title}: ${pr.url}`);
  return what;
}
function prBody2(b) {
  const link = (v) => `[${safe3(v.id)}](${advisoryUrl(v.id)})`;
  const idLink = (id) => `[${safe3(id)}](${advisoryUrl(id)})`;
  const out = [];
  if (b.fixed.length) {
    out.push(
      `Security fixes from decant audit: ${plural(b.fixed.length, "package", "packages")} upgraded to versions that fix their advisories.`,
      "",
      "| Package | From \u2192 To | Advisories | Severity |",
      "|---|---|---|---|",
      ...b.fixed.map(
        (p) => `| \`${safe3(p.name)}\` | ${oldsOf(p).map(safe3).join(", ")} \u2192 ${targetsOf(p).map(safe3).join(", ")} | ${p.vulns.map(link).join(", ")} | ${maxSev(p.vulns.map(sevOf))} |`
      ),
      ""
    );
  }
  if (b.bumps.length) {
    const short2 = (d) => d.slice(0, "sha256:".length + 12);
    out.push(
      `Base image digest bumps: ${plural(b.bumps.length, "image", "images")} moved to the digest its tag points at now. Each new digest has cleared the ${b.cooldownDays}-day cooldown (counted from when decant first verified it) and removes the High/Critical findings listed.`,
      "",
      "| Image | From \u2192 To | Fixes | Severity |",
      "|---|---|---|---|",
      ...b.bumps.map(
        (x) => `| \`${safe3(x.name)}:${safe3(x.tag)}\` | ${short2(x.from)} \u2192 ${short2(x.to)} | ${x.fixes.slice(0, 10).map((f) => idLink(f.id)).join(", ")}${x.fixes.length > 10 ? ", \u2026" : ""} | ${x.severity} |`
      ),
      ""
    );
    const intro = b.bumps.flatMap((x) => x.introduced.map((f) => `- \`${safe3(x.name)}:${safe3(x.tag)}\` ${idLink(f.id)} (${f.severity}) in \`${safe3(f.package)}\` ${safe3(f.version)}`));
    if (intro.length) out.push("**Introduced by the new digests** (below High; counted for the approval rules):", ...intro.slice(0, 30), ...intro.length > 30 ? [`- \u2026and ${intro.length - 30} more`] : [], "");
  }
  const summaries = b.fixed.flatMap((p) => p.vulns.filter((v) => v.summary).map((v) => `- ${link(v)}: ${cell(v.summary, 200)}`));
  if (summaries.length) out.push("<details><summary>Advisory summaries</summary>", "", ...[...new Set(summaries)], "", "</details>", "");
  if (b.left.length) {
    out.push("**Not included** (see the `decant: unfixed advisories` issue):");
    const label = { fixed: "fixed", declined: "declined", unverified: "not verified", unresolvable: "unresolvable", failed: "failed" };
    for (const o of b.left) out.push(`- \`${safe3(o.pkg.name)}\` ${oldsOf(o.pkg).map(safe3).join(", ")}: ${label[o.result]}: ${cell(o.detail)}`);
    out.push("");
  }
  if (b.unfixed.length) {
    const rows = [...new Map(b.unfixed.map((u) => [`${u.vuln.id}|${depKey(u.dep)}`, u])).values()];
    out.push("**No fixed release yet** (tracked in the `decant: unfixed advisories` issue):");
    for (const u of rows.slice(0, 30)) out.push(`- ${link(u.vuln)} \`${safe3(u.dep.name)}@${safe3(u.dep.version)}\``);
    if (rows.length > 30) out.push(`- \u2026and ${rows.length - 30} more`);
    out.push("");
  }
  if (b.added.length) {
    out.push(
      `**Cooldown skip:** this PR adds \`allow\` entries for ${b.added.map((a) => `\`${safe3(a.package)}\``).join(", ")}, each citing its advisory, so the fixed versions ship without waiting out the ${b.cooldownDays}-day cooldown. decant honors each only while OSV lists that version as fixed; none is exempt from the scan.`,
      ""
    );
  }
  out.push("Files:", ...b.paths.map((p) => `- \`${p}\``), "");
  if (b.auto) out.push("Every advisory severity here has autoShip `auto` and no upgrade crosses a major line: auto-merge is on; it merges once the required checks (including the decant scan) pass.");
  else {
    out.push("Auto-merge is off; review and merge.");
    if (b.majors.length) {
      out.push(`- **major upgrade: auto-merge disabled.** ${b.majors.map((p) => `\`${safe3(p.name)}\``).join(", ")} crosses a major (or 0.x minor) version line.`);
    }
    for (const s of b.approve) out.push(`- autoShip.${s} is \`approve\`.`);
  }
  out.push("", `<!-- decant-audit-set: ${b.hash} -->`);
  return out.join("\n");
}
function baseEnv(env, names) {
  const out = {};
  for (const n of names) if (env[n] !== void 0) out[n] = env[n];
  return out;
}
async function run1(deps, cmd, args, cwd, env, secrets) {
  const r = await deps.exec(cmd, args, { cwd, env });
  if (r.code !== 0) {
    const what = [args[0], ...args.slice(args.indexOf("--") + 1 || args.length)].join(" ");
    const why = redact((r.stderr || r.stdout).trim().split("\n").slice(-3).join(" "), secrets).slice(0, 300);
    throw new PkgError("failed", `${cmd} ${what} exited ${r.code}: ${why}`);
  }
}
async function stale(ctx, abs, p) {
  const deps = parsePackageLock(await ctx.deps.fs.readFile(abs), abs, ctx.inputs.decantUrl);
  const out = [];
  for (const d of deps) {
    if (d.name !== p.name) continue;
    const target2 = targetFor(p.vulns, "npm", d.name, d.version);
    if (target2 !== null) out.push({ dep: d, target: target2, vulns: [] });
  }
  return out;
}
async function fixNpm(ctx, p, dir, track) {
  const { deps, inputs } = ctx;
  const lockAbs = `${dir}/package-lock.json`;
  const pkgAbs = `${dir}/package.json`;
  await track(lockAbs);
  await track(pkgAbs);
  const base = inputs.decantUrl.replace(/\/+$/, "");
  const url = new URL(base);
  const registry = `${base}/r/${OVERLAY_REF}/npm/`;
  const userconfig = await ctx.tmpFile("npmrc");
  const env = baseEnv(deps.env, ["PATH", "HOME", "RUNNER_TEMP"]);
  const common = ["--userconfig", userconfig, "--registry", registry, "--ignore-scripts", "--package-lock-only", "--no-audit", "--no-fund"];
  const npm = (cmd, specs) => run1(deps, "npm", [cmd, ...common, ...specs.length ? ["--", ...specs] : []], dir, env, [inputs.token]);
  await deps.fs.writeFile(userconfig, `registry=${registry}
//${url.host}${url.pathname.replace(/\/+$/, "")}/r/${OVERLAY_REF}/npm/:_authToken=${inputs.token}
ignore-scripts=true
`, 384);
  try {
    await deps.fs.chmod(userconfig, 384);
    const pkgText = await deps.fs.exists(pkgAbs) ? await deps.fs.readFile(pkgAbs) : null;
    const pkg = pkgText === null ? null : JSON.parse(pkgText);
    const declared = !!pkg && ["dependencies", "devDependencies", "optionalDependencies"].some((k) => pkg[k]?.[p.name] !== void 0);
    const lock = JSON.parse(await deps.fs.readFile(lockAbs));
    const topVersion = lock.packages?.[`node_modules/${p.name}`]?.version;
    const topTarget = declared && topVersion ? targetFor(p.vulns, "npm", p.name, topVersion) : null;
    if (topTarget !== null) {
      await npm("install", [`${p.name}@${topTarget}`]);
    } else {
      await npm("update", [p.name]);
      const left2 = await stale(ctx, lockAbs, p);
      if (left2.length) {
        if (!pkg || pkgText === null) throw new PkgError("unresolvable", `${ctx.repoPath(lockAbs)}: no package.json for an override`);
        const overrides = { ...pkg.overrides ?? {} };
        const byKey = /* @__PURE__ */ new Map();
        for (const c of left2) {
          const k = overrideKey(p.name, c.dep.version);
          const prev = byKey.get(k);
          if (!prev || compareVersions(c.target, prev, "npm") > 0) byKey.set(k, c.target);
        }
        for (const [k, v] of [...byKey].sort(([a], [b]) => a < b ? -1 : 1)) overrides[k] = v;
        pkg.overrides = overrides;
        const indent = /^\{\n(\s+)/.exec(pkgText)?.[1] ?? "  ";
        await deps.fs.writeFile(pkgAbs, `${JSON.stringify(pkg, null, indent)}${pkgText.endsWith("\n") ? "\n" : ""}`);
        await npm("install", []);
      }
    }
  } finally {
    await deps.fs.rm(userconfig);
  }
  const n = normalizeLockfile(await deps.fs.readFile(lockAbs), inputs.decantUrl);
  if (n.changed) await deps.fs.writeFile(lockAbs, n.text);
  const left = await remaining(ctx, p, dir);
  if (left.length) throw new PkgError("unresolvable", left.join("; "));
}
async function fixGo(ctx, p, dir, track) {
  const { deps, inputs } = ctx;
  await track(`${dir}/go.mod`);
  await track(`${dir}/go.sum`);
  const here = p.copies.filter((c) => dirname(join3(ctx.wd, c.dep.file)) === dir).map((c) => c.target);
  const target2 = uniqSorted(here.length ? here : targetsOf(p), "go").at(-1);
  const base = inputs.decantUrl.replace(/\/+$/, "");
  const netrc = await ctx.tmpFile("netrc");
  const env = {
    ...baseEnv(deps.env, ["PATH", "HOME", "GOPATH", "GOCACHE"]),
    NETRC: netrc,
    GOPROXY: `${base}/r/${OVERLAY_REF}/go`,
    GOFLAGS: "-mod=mod"
  };
  await deps.fs.writeFile(netrc, `machine ${new URL(base).hostname} login decant password ${inputs.token}
`, 384);
  try {
    await deps.fs.chmod(netrc, 384);
    await run1(deps, "go", ["get", "--", `${p.name}@${target2}`], dir, env, [inputs.token]);
    await run1(deps, "go", ["mod", "tidy"], dir, env, [inputs.token]);
  } finally {
    await deps.fs.rm(netrc);
  }
  const left = await remaining(ctx, p, dir);
  if (left.length) throw new PkgError("unresolvable", left.join("; "));
}
async function syncIssue(gh, title, body) {
  if (body !== null) return (await gh.upsertIssue(title, body, ISSUE_LABELS)).number;
  const n = await gh.findIssue(title, ISSUE_LABELS);
  if (n !== null) {
    await gh.closeIssue(n);
    notice(`closed #${n} (${title})`);
  }
  return null;
}
function unfixedBody(items) {
  const rows = [...new Map(items.map((i) => [`${i.vuln.id}|${depKey(i.dep)}|${i.dep.file}`, i])).values()].sort(
    (a, b) => a.vuln.id < b.vuln.id ? -1 : a.vuln.id > b.vuln.id ? 1 : 0
  );
  return [
    "Advisories affecting locked versions that decant could not fix automatically: no usable fixed release, or the fix could not be verified or resolved. decant updates this issue daily and closes it when none remain.",
    "",
    "| Advisory | Severity | Package | Lockfile | Reason |",
    "|---|---|---|---|---|",
    ...rows.map((i) => `| [${safe3(i.vuln.id)}](${advisoryUrl(i.vuln.id)}) | ${i.vuln.malicious ? "malicious" : i.vuln.severity} | \`${safe3(i.dep.name)}@${safe3(i.dep.version)}\` | ${safe3(i.dep.file)} | ${i.reason} |`)
  ].join("\n");
}
function blockedBody(hits) {
  return [
    "Versions in the lockfiles that decant blocks globally. Installs of these fail; upgrade or remove them. decant closes this issue when none remain.",
    "",
    "| Package | Source | Reason | Lockfiles |",
    "|---|---|---|---|",
    ...hits.map((h) => `| \`${safe3(h.package)}\` | ${safe3(h.source)} | ${h.reason.replace(/[|\n<>]/g, " ").slice(0, 200)} | ${h.files.map(safe3).join(", ")} |`)
  ].join("\n");
}
async function pruneAllow(ctx, now) {
  const { deps, gh } = ctx;
  const allow = ctx.raw.allow ?? [];
  const expired = [];
  let unknown = 0;
  for (const e of allow) {
    const p = parsePackageId(e.package);
    if (!p) continue;
    let at = null;
    try {
      at = p.eco === "npm" ? await npmPublishTime(deps.fetch, p.name, p.version) : await goPublishTime(deps.fetch, p.name, p.version);
    } catch (err) {
      warning(`prune: ${safe3(e.package)}: ${err.message}`);
    }
    if (!at) {
      unknown++;
      continue;
    }
    if (at.getTime() + ctx.policy.cooldownDays * DAY2 <= now.getTime()) expired.push({ e, at });
  }
  if (!expired.length) return `nothing expired${unknown ? ` (${unknown} publish time(s) unknown)` : ""}`;
  const gone = new Set(expired.map((x) => x.e));
  const next = { ...ctx.raw, allow: allow.filter((e) => !gone.has(e)) };
  const contents = `${JSON.stringify(next, null, 2)}
`;
  const files = [{ path: ctx.policyRel, contents }];
  const body = [
    `These \`allow\` entries have aged past the ${ctx.policy.cooldownDays}-day cooldown and no longer do anything. Review, then merge (never auto-merged).`,
    "",
    "| package | reason | published |",
    "| --- | --- | --- |",
    ...expired.map((x) => `| ${safe3(x.e.package)} | ${x.e.reason.replace(/[|\n<>]/g, " ").slice(0, 100)} | ${ymd2(x.at)} |`)
  ].join("\n");
  const title = "decant: prune allow entries";
  const open = await gh.findOpenPr(PRUNE_BRANCH);
  const base = ctx.base;
  let head;
  if (open) {
    head = open.headSha;
    if (await gh.fileAt(ctx.policyRel, head) === contents) return `PR #${open.number} up to date (${expired.length} entr${expired.length === 1 ? "y" : "ies"})`;
  } else {
    head = ctx.sha;
    try {
      await gh.createBranch(PRUNE_BRANCH, head);
    } catch (e) {
      if (!/HTTP 422/.test(e.message)) throw e;
      await gh.updateRef(PRUNE_BRANCH, head);
    }
  }
  await gh.commitFiles(PRUNE_BRANCH, head, title, files);
  if (open) {
    await gh.updatePr(open.number, { body });
    return `updated PR #${open.number} (${expired.length} expired)`;
  }
  const pr = await gh.openPr({ head: PRUNE_BRANCH, base, title, body, labels: ["decant:prune"] });
  notice(`${title}: ${pr.url}`);
  return `opened PR #${pr.number} (${expired.length} expired)`;
}

// action/src/modes/scan.ts
var scan_exports = {};
__export(scan_exports, {
  MARKER: () => MARKER,
  run: () => run3
});
import { join as join5 } from "node:path";
import { tmpdir as tmpdir2 } from "node:os";

// action/src/docker-gate.ts
import { join as join4 } from "node:path";
import { tmpdir } from "node:os";

// action/src/git.ts
var SHA_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
async function fileAtCommit(deps, wd, sha, rel) {
  const r = await deps.exec("git", ["show", `${sha}:./${rel}`], { cwd: wd });
  if (r.code === 0) return r.stdout;
  if (/does not exist in|exists on disk, but not in/.test(r.stderr)) return null;
  throw new Error(
    `git show ${sha.slice(0, 12)}:${rel} failed: ${r.stderr.trim().slice(0, 300)} (actions/checkout needs fetch-depth: 0)`
  );
}

// action/src/docker-gate.ts
var safe4 = (s) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, "?");
var safeLine = (s) => s.replace(/[^A-Za-z0-9@._~/+:= #=$-]/g, "?");
var safeText = (s) => s.replace(/\s+/g, " ").replace(/[^A-Za-z0-9._~/+:,;=!?#%&*()'"{}$^@ -]/g, "?");
var MAX_IMAGES = 200;
var MAX_LISTED = 5;
var fmtTime = (iso) => `${iso.slice(0, 16).replace("T", " ")} UTC`;
function findingList(fs) {
  const shown = fs.slice(0, MAX_LISTED).map((f) => `${safe4(f.id)} (${safe4(f.package)} ${safe4(f.version)}${f.fixed.length ? ` \u2192 ${safe4(f.fixed[0])}` : ""})`);
  return `${shown.join(", ")}${fs.length > MAX_LISTED ? `, +${fs.length - MAX_LISTED} more` : ""}`;
}
function pinned(f, digest) {
  const base = f.text.replace(/@sha256:[0-9a-f]*$/, "");
  if (f.syntax) return `# syntax=${base}@${digest}`;
  if (f.via === "copy") return `COPY --from=${base}@${digest}`;
  if (f.via === "mount") return `RUN --mount=from=${base}@${digest}`;
  return `FROM ${f.platform ? `--platform=${f.platform} ` : ""}${base}@${digest}`;
}
async function changedDockerfiles(deps, wd, baseSha) {
  const tree = await findDockerfiles(wd, deps.fs);
  const changed = [];
  const unchanged = [];
  for (const rel of tree.files) {
    if (await fileAtCommit(deps, wd, baseSha, rel) !== await deps.fs.readFile(join4(wd, rel))) changed.push(rel);
    else unchanged.push(rel);
  }
  return { changed, unchanged, symlinks: tree.symlinks };
}
async function dockerGate(o) {
  const { deps, wd, baseSha, ref, client } = o;
  const env = deps.env;
  const rows = [];
  const files = await changedDockerfiles(deps, wd, baseSha);
  if (files.symlinks.length) return { rows, fatal: `symlinked Dockerfile or directory (${files.symlinks.map(safe4).join(", ")}); decant does not scan through symlinks` };
  if (!files.changed.length) return { rows, fatal: null };
  const atBase = /* @__PURE__ */ new Set();
  const addBase = (text) => {
    if (text === null) return;
    for (const f of parseDockerfile(text).froms) if (f.kind === "image" && f.ref?.digest) atBase.add(`${f.ref.name}@${f.ref.digest}`);
  };
  for (const rel of files.unchanged) addBase(await deps.fs.readFile(join4(wd, rel)));
  for (const rel of files.changed) addBase(await fileAtCommit(deps, wd, baseSha, rel));
  const oci = ociClient({ fetch: deps.fetch });
  const candidates = /* @__PURE__ */ new Map();
  for (const rel of files.changed) {
    const parsed = parseDockerfile(await deps.fs.readFile(join4(wd, rel)));
    for (const e of parsed.errors) {
      rows.push({ file: rel, line: Number(/^line (\d+)/.exec(e)?.[1] ?? 0), image: "\u2014", cooldown: "\u2014", grype: "\u2014", problems: ["cannot read this line (see log)"], notes: [] });
      error(safeText(e.replace(/^line (\d+): /, `${rel}:$1: `)), join4(wd, rel));
    }
    for (const a of parsed.argLines ?? []) {
      warning(`${safe4(rel)}:${a.line}: --mount value comes from ${a.args.map((x) => `ARG ${safe4(x)}`).join(", ")}; a --build-arg at build time bypasses this check`, join4(wd, rel));
    }
    for (const f of parsed.froms) {
      if (f.args?.length) {
        warning(
          `${safe4(rel)}:${f.line}: value comes from ${f.args.map((a) => `ARG ${safe4(a)}`).join(", ")}; a --build-arg at build time bypasses this check`,
          join4(wd, rel)
        );
      }
      if (f.kind !== "image" || !f.ref) continue;
      const r = f.ref;
      if (r.digest) {
        const k = `${r.name}@${r.digest}`;
        if (atBase.has(k)) continue;
        const c = candidates.get(k) ?? { name: r.name, digest: r.digest, platform: f.platform, uses: [] };
        c.uses.push({ file: rel, line: f.line });
        candidates.set(k, c);
        continue;
      }
      const res = await oci.resolveTag(r.name, r.tag ?? "latest");
      const fix = res.status === "ok" ? `pin it: \`${safeLine(pinned(f, res.digest))}\`` : res.status === "unsupported" ? `can't resolve: registry ${safe4(r.registry)} is not supported; pin the digest you build from` : res.status === "denied" ? "can't resolve: anonymous pull refused (private image?); pin the digest you build from" : `can't resolve the tag (${res.status === "not-found" ? "not found" : safeText(res.message)})`;
      const what = f.syntax ? "syntax frontend image is not pinned by digest" : f.via ? `${f.via === "copy" ? "COPY --from" : "RUN --mount from"} image is not pinned by digest` : "not pinned by digest";
      rows.push({ file: rel, line: f.line, image: safe4(f.text), cooldown: "\u2014", grype: "\u2014", problems: [`${what}; ${fix}`], notes: [] });
      error(`${safe4(rel)}:${f.line}: ${safe4(f.text)} is ${what}; ${fix.replace(/`/g, "")}`, join4(wd, rel));
    }
  }
  if (candidates.size > MAX_IMAGES) return { rows, fatal: `too many new image digests (${candidates.size}); split the change` };
  if (!candidates.size) return { rows, fatal: null };
  const list = [...candidates.values()];
  const reply = await client.images(ref, list.map((c) => ({ name: c.name, digest: c.digest })));
  const decisions = new Map(reply.images.map((d) => [`${d.name}@${d.digest}`, d]));
  let installed = null;
  const grype = () => installed ??= installGrype(deps.fetch, deps.exec, deps.fs, `${env.RUNNER_TEMP || tmpdir()}/decant-grype`, grypeArch(env.DECANT_GRYPE_PLATFORM || process.platform, env.DECANT_GRYPE_ARCH || process.arch)).then((g) => g.bin);
  const grypeEnvs = grypeEnv(`${env.RUNNER_TEMP || tmpdir()}/decant-grype-db`);
  for (const c of list) {
    const id = formatPackageId({ eco: "docker", name: c.name, version: c.digest });
    const use = c.uses[0];
    const row = { file: use.file, line: use.line, image: safe4(`${c.name}@${c.digest}`), cooldown: "\u2014", grype: "\u2014", problems: [], notes: [] };
    rows.push(row);
    if (c.uses.length > 1) row.notes.push(`also ${c.uses.slice(1).map((u) => `${safe4(u.file)}:${u.line}`).join(", ")}`);
    const d = decisions.get(`${c.name}@${c.digest}`);
    if (!d) {
      row.problems.push("decant returned no decision");
      continue;
    }
    if (d.decision === "blocked") {
      row.cooldown = "blocked";
      row.problems.push(`blocked by decant (${d.blocks.map((b) => `${safe4(b.source)}: ${b.reason.replace(/[|\n<>`]/g, " ").slice(0, 100)}`).join("; ")})`);
      continue;
    }
    if (d.decision === "allow") row.cooldown = d.allowed ? "allowed by policy" : `cleared (first seen ${fmtTime(d.firstSeen)})`;
    else if (d.clock === "unverified") {
      row.cooldown = "not verified";
      row.problems.push(`decant could not verify this digest in the registry (${safeText(d.note ?? "unknown")}); it stays in cooldown until it can`);
    } else {
      row.cooldown = `until ${fmtTime(d.eligibleAt)}`;
      row.problems.push(`waiting for cooldown until ${fmtTime(d.eligibleAt)} (first seen by decant ${fmtTime(d.firstSeen)}${d.clock === "project" ? ", this project only" : ""})`);
    }
    const cached = await client.getVerdicts(id);
    if (cached.some((v) => v.result === "malicious")) row.problems.push(`malicious (${cached.filter((v) => v.result === "malicious").map((v) => safe4(v.scanner)).join(", ")})`);
    const registry = c.name.slice(0, c.name.indexOf("/"));
    if (!isKnownRegistry(registry)) {
      row.grype = "not scanned";
      if (d.allowed) row.notes.push(`registry ${safe4(registry)} is not scannable; accepted by an allow entry`);
      else row.problems.push(`not scannable: decant scans Docker Hub and ghcr.io images only; add an allow entry for ${safe4(id)} to accept it`);
      continue;
    }
    try {
      const res = await scanImage(deps.exec, await grype(), c.name, c.digest, grypeEnvs, c.platform);
      const v = grypeVerdict(res);
      await client.putVerdict({ package: id, scanner: "grype", scannerVersion: GRYPE_VERSION, result: v.result, details: v.details });
      row.grype = res.failing.length ? `${res.failing.length} fixable High/Critical` : res.unfixed.length ? `${res.unfixed.length} High/Critical, no fix` : "clean";
      if (res.failing.length) row.problems.push(`vulnerable: ${findingList(res.failing)}`);
      if (res.unfixed.length) {
        row.notes.push(`no fix yet: ${findingList(res.unfixed)}`);
        warning(`${row.image}: ${res.unfixed.length} High/Critical finding(s) with no fix yet`);
      }
    } catch (e) {
      row.grype = "scan error";
      row.problems.push("scan error (see log)");
      error(`${row.image}: ${safeText(e.message).slice(0, 300)}`);
    }
  }
  return { rows, fatal: null };
}
function renderImages(rows, limit = Infinity) {
  if (!rows.length) return [];
  const out = ["", "### Base images", "", "| Image | Dockerfile | Cooldown | Grype | Status |", "|---|---|---|---|---|"];
  let size2 = out.join("\n").length;
  for (const [i, r] of rows.entries()) {
    const status = r.problems.length ? `\u274C ${r.problems.join("; ")}` : `\u2705 ${r.notes.length ? r.notes.join("; ") : "ok"}`;
    const line2 = `| ${r.image === "\u2014" ? "\u2014" : `\`${r.image}\``} | ${safe4(r.file)}:${r.line} | ${r.cooldown} | ${r.grype} | ${status.replace(/\|/g, "\\|")} |`;
    if (size2 + line2.length + 1 > limit) {
      out.push(`
\u2026 and ${rows.length - i} more image row(s) (see the job summary).`);
      break;
    }
    out.push(line2);
    size2 += line2.length + 1;
  }
  return out;
}
var OTHER_IMAGE_FILES = /^(?:(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml|fly\.toml)$/;
async function otherImageFiles(deps, wd) {
  const out = [];
  const base = wd.replace(/\/+$/, "");
  const skip = /* @__PURE__ */ new Set(["node_modules", ".git", "vendor", "testdata"]);
  async function walk(rel) {
    for (const e of await deps.fs.readdir(rel ? `${base}/${rel}` : base)) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymlink) continue;
      if (e.isDir) {
        if (!skip.has(e.name)) await walk(r);
      } else if (OTHER_IMAGE_FILES.test(e.name)) out.push(r);
    }
  }
  await walk("");
  return out.sort();
}

// action/src/event.ts
async function readPayload(deps) {
  const p = deps.env.GITHUB_EVENT_PATH;
  if (!p) return {};
  try {
    return JSON.parse(await deps.fs.readFile(p));
  } catch {
    throw new Error(`cannot read event payload at ${p}`);
  }
}
function isForkPr(payload) {
  const head = payload.pull_request?.head?.repo;
  return !head || head.full_name !== payload.repository?.full_name;
}

// action/src/guarddog.ts
import { fileURLToPath } from "node:url";
var GUARDDOG_VERSION = "3.2.0";
var MAX_LOCATIONS = 5;
var MAX_MESSAGE = 200;
var MAX_RULE = 100;
var MAX_LOCATION = 200;
function clip2(s, n) {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n - 1)}\u2026` : t;
}
function finding(rule, count2, message, locations) {
  const f = { rule: clip2(rule, MAX_RULE) };
  if (count2 !== void 0) f.count = count2;
  if (typeof message === "string" && message.trim()) f.message = clip2(message, MAX_MESSAGE);
  const locs = [...new Set(locations.filter((l) => typeof l === "string" && l.trim() !== "").map((l) => clip2(l, MAX_LOCATION)))];
  if (locs.length) f.locations = locs.slice(0, MAX_LOCATIONS);
  return f;
}
function normalizeFindings(details) {
  if (!Array.isArray(details)) return [];
  const out = [];
  for (const d of details) {
    if (typeof d === "string" && d.trim()) out.push({ rule: clip2(d, MAX_RULE) });
    else if (d && typeof d === "object" && typeof d.rule === "string") {
      const o = d;
      const count2 = typeof o.count === "number" && Number.isInteger(o.count) && o.count >= 0 ? o.count : void 0;
      out.push(finding(o.rule, count2, o.message, Array.isArray(o.locations) ? o.locations : []));
    }
  }
  return out;
}
function tail2(s) {
  return s.trim().split("\n").slice(-5).join(" ").slice(0, 500);
}
function actionDir(override, moduleUrl = import.meta.url) {
  return override || fileURLToPath(new URL("..", moduleUrl));
}
function requirementsPath(actionPath) {
  return `${actionPath.replace(/\/+$/, "")}/guarddog-requirements.txt`;
}
function pythonInterpreter(env) {
  if (env.DECANT_PYTHON) return env.DECANT_PYTHON;
  if (env.pythonLocation) return `${env.pythonLocation.replace(/\/+$/, "")}/bin/python`;
  return "python3";
}
function supportedPythons(requirements) {
  const m = /^# decant-python:([ \d.]+)$/m.exec(requirements);
  const versions = (m?.[1] ?? "").trim().split(/\s+/).filter((v) => /^3\.\d+$/.test(v));
  if (versions.length === 0) throw new Error('guarddog-requirements.txt has no "# decant-python:" header');
  return versions;
}
async function installGuardDog(exec, readFile2, dir, actionPath, env) {
  const req = requirementsPath(actionPath);
  const supported = supportedPythons(await readFile2(req));
  const python = pythonInterpreter(env);
  const ver = await exec(python, ["-c", 'import sys; print("%d.%d" % sys.version_info[:2])']);
  if (ver.code !== 0) throw new Error(`${python} failed to run: ${tail2(ver.stderr)}`);
  const found = ver.stdout.trim();
  if (!supported.includes(found)) {
    throw new Error(
      `GuardDog's pinned dependencies are built for Python ${supported.join(" or ")}, but ${python} is ${found || "unknown"}; add actions/setup-python with python-version: '${supported[0]}' before the decant scan step (see docs/adopt.md)`
    );
  }
  const venv = await exec(python, ["-m", "venv", dir]);
  if (venv.code !== 0) throw new Error(`${python} -m venv failed: ${tail2(venv.stderr)}`);
  const pip = await exec(`${dir}/bin/pip`, [
    "install",
    "--disable-pip-version-check",
    "--require-hashes",
    "--no-deps",
    "--only-binary",
    ":all:",
    "-r",
    req
  ]);
  if (pip.code !== 0) throw new Error(`pip install of GuardDog failed: ${tail2(pip.stderr)}`);
  return { bin: `${dir}/bin/guarddog` };
}
var hasFindings = (v) => Array.isArray(v) ? v.length > 0 : typeof v === "object" && v !== null ? Object.keys(v).length > 0 : typeof v === "string" ? v !== "" : !!v;
function parseGuardDogJson(stdout) {
  let doc;
  try {
    doc = JSON.parse(stdout);
  } catch {
    throw new Error("guarddog: invalid JSON output");
  }
  if (doc.errors && typeof doc.errors === "object" && Object.keys(doc.errors).length > 0) {
    throw new Error(`guarddog reported errors: ${Object.keys(doc.errors).join(", ")}`);
  }
  if (!doc.results || typeof doc.results !== "object") throw new Error("guarddog: no results in output");
  const details = [];
  for (const [rule, v] of Object.entries(doc.results).sort(([a], [b]) => a < b ? -1 : 1)) {
    if (rule.startsWith("capability-") || !hasFindings(v)) continue;
    if (Array.isArray(v)) {
      const hits = v.map((h) => h && typeof h === "object" ? h : {});
      details.push(finding(rule, v.length, hits.map((h) => h.message).find((m) => typeof m === "string" && m.trim()), hits.map((h) => h.location)));
    } else {
      details.push(finding(rule, void 0, v, []));
    }
  }
  if (Array.isArray(doc.risks) && doc.risks.length > 0) {
    const label = typeof doc.risk_score?.label === "string" ? doc.risk_score.label : "unlabelled";
    const locs = doc.risks.map((r) => r && typeof r === "object" ? r.threat_location : void 0);
    details.push(finding("risk", doc.risks.length, label, locs));
  }
  return { result: details.length > 0 ? "flagged" : "clean", details };
}
var ARCHIVE_ANOMALY = "archive-anomaly";
var ANOMALY_REASONS = [
  {
    re: /^multiple End-Of-Central-Directory records \(possible scan evasion via duplicate EOCD\)$/,
    text: () => "multiple End-Of-Central-Directory records (possible scan evasion via duplicate EOCD)"
  },
  {
    re: /^(\d{1,9}) ZIP local file headers but zipfile enumerates (\d{1,9}) members from the central directory \(possible scan evasion via EOCD size\/offset differential\)$/,
    text: (m) => `${Number(m[1])} ZIP local file headers but zipfile enumerates ${Number(m[2])} members from the central directory (possible scan evasion via EOCD size/offset differential)`
  }
];
function archiveAnomaly(r, path) {
  if (r.code !== 1 || r.stdout.trim() !== "") return null;
  const lines = r.stderr.split("\n").filter((l) => l.trim() !== "");
  if (lines.length !== 1) return null;
  const prefix = `ERROR: Error occurred while scanning target ${path}: 'archive parser anomaly: `;
  const line2 = lines[0].replace(/\r$/, "");
  if (!line2.startsWith(prefix) || !line2.endsWith("'")) return null;
  const reason = line2.slice(prefix.length, -1);
  for (const { re, text } of ANOMALY_REASONS) {
    const m = re.exec(reason);
    if (m) return `archive parser anomaly: ${text(m)}`;
  }
  return null;
}
async function scan(exec, bin, eco, path) {
  const r = await exec(bin, [eco, "scan", path, "--output-format", "json", "--sandbox"]);
  if (r.code !== 0) {
    const anomaly = archiveAnomaly(r, path);
    if (anomaly) return { result: "flagged", details: [{ rule: ARCHIVE_ANOMALY, message: anomaly }] };
    throw new Error(`guarddog ${eco} scan exited ${r.code}: ${tail2(r.stderr)}`);
  }
  return parseGuardDogJson(r.stdout);
}
var scanNpm = (exec, bin, tgzPath) => scan(exec, bin, "npm", tgzPath);
var scanGo = (exec, bin, zipPath) => scan(exec, bin, "go", zipPath);

// action/src/modes/scan.ts
var MARKER = "<!-- decant-scan -->";
var MAX_DEPS2 = 500;
var CONCURRENCY2 = 4;
var REVIEWED = "decant:reviewed";
var SECURITY = "decant:security";
var OSV_SCANNER_VERSION = "api.osv.dev/v1";
var COMMENT_LIMIT = 6e4;
var SEV_RANK = { low: 1, moderate: 2, unknown: 2, high: 3, critical: 4 };
var RESULT_RANK = { clean: 0, flagged: 1, malicious: 2 };
function fail(msg) {
  error(msg);
  process.stderr.write(`${msg}
`);
  return 1;
}
var safe5 = (s) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, "?");
var safeText2 = (s) => s.replace(/\s+/g, " ").replace(/[^A-Za-z0-9._~/+:,;=!?#%&*()'"{}$^ -]/g, "?");
var count = (f) => f.count !== void 0 ? ` (${f.count})` : "";
var NOT_SCANNED = "contents NOT scanned by GuardDog (archive anomaly; can be deliberate scan evasion). Inspect the archive manually before adding decant:reviewed";
var notScanned = (f) => f.rule === ARCHIVE_ANOMALY;
function findingText(f) {
  const msg = f.message ? `: ${safeText2(f.message)}` : "";
  const at = f.locations?.length ? ` at ${f.locations.map(safeText2).join(", ")}` : "";
  return `${safe5(f.rule)}${count(f)}${msg}${at}${notScanned(f) ? ` - ${NOT_SCANNED}` : ""}`;
}
function findingLine(r, f) {
  const msg = f.message ? `: \`${safeText2(f.message)}\`` : "";
  const at = f.locations?.length ? ` at ${f.locations.map((l) => `\`${safeText2(l)}\``).join(", ")}` : "";
  return `- \`${safe5(r.dep.name)}@${safe5(r.dep.version)}\` \`${safe5(f.rule)}\`${count(f)}${msg}${at}${notScanned(f) ? ` \u26A0\uFE0F **${NOT_SCANNED}**` : ""}`;
}
var isPackageLock2 = (rel) => rel === "package-lock.json" || rel.endsWith("/package-lock.json");
var shellQuote = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
function newReviewScope(p) {
  return p.action === "synchronize" || p.action === "reopened" || p.action === "edited" && !!p.changes?.base;
}
var fmtTime2 = (d) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
async function pool(items, n, fn) {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
}
function parseLock(rel, text, decantUrl) {
  return isPackageLock2(rel) ? parsePackageLock(text, rel, decantUrl) : parseGoSum(text, rel);
}
async function cooldownNote(deps, dep, cooldownDays) {
  try {
    const t = dep.eco === "npm" ? await npmPublishTime(deps.fetch, dep.name, dep.version) : await goPublishTime(deps.fetch, dep.name, dep.version);
    if (t) return `waiting for cooldown until ${fmtTime2(new Date(t.getTime() + cooldownDays * 864e5))}`;
  } catch {
  }
  return "waiting for cooldown (publish time unknown)";
}
function render(rows, pass, failOn, ref, limit = Infinity, note = "", images = []) {
  const imageText = renderImages(images, limit === Infinity ? Infinity : Math.floor(limit / 3)).join("\n");
  if (limit !== Infinity) limit -= imageText.length;
  const head = [
    MARKER,
    `## decant scan: ${pass ? "\u2705 pass" : "\u274C fail"}`,
    "",
    ...note ? [note, ""] : [],
    `${rows.length} new dependency version${rows.length === 1 ? "" : "s"} (ref \`${ref}\`, fail-on \`${failOn}\`).`,
    "",
    "| Package | Source | OSV | GuardDog | Vulns | Status |",
    "|---|---|---|---|---|---|"
  ].join("\n");
  const lines = [];
  let size2 = head.length;
  let cut = false;
  for (const [i, r] of rows.entries()) {
    const vulns = r.vulns.length ? r.vulns.map((v) => `${safe5(v.id)} (${v.malicious ? "malicious" : v.severity})`).join(", ") : "\u2014";
    const status = r.problems.length ? `\u274C ${r.problems.join("; ")}` : r.warn ? `\u26A0\uFE0F ${r.notes.join("; ")}` : `\u2705 ${r.notes.length ? r.notes.join("; ") : "ok"}`;
    const source = r.dep.source === "registry" ? r.dep.eco : "other";
    const line2 = `| \`${safe5(r.dep.name)}@${safe5(r.dep.version)}\` | ${source} | ${r.osv} | ${r.guarddog} | ${vulns} | ${status} |`;
    if (size2 + line2.length + 1 > limit) {
      lines.push(`
\u2026 and ${rows.length - i} more (see the job summary).`);
      cut = true;
      break;
    }
    lines.push(line2);
    size2 += line2.length + 1;
  }
  const findings = rows.filter((r) => r.flagged).flatMap((r) => r.findings.length ? r.findings.map((f) => findingLine(r, f)) : [`- \`${safe5(r.dep.name)}@${safe5(r.dep.version)}\` (no rule details recorded)`]);
  if (findings.length && !cut) {
    const title = "\n### GuardDog findings\n";
    lines.push(title);
    size2 += title.length + 1;
    for (const [i, line2] of findings.entries()) {
      if (size2 + line2.length + 1 > limit) {
        lines.push(`
\u2026 and ${findings.length - i} more finding${findings.length - i === 1 ? "" : "s"} (see the job summary).`);
        break;
      }
      lines.push(line2);
      size2 += line2.length + 1;
    }
  }
  return `${head}
${lines.join("\n")}
${imageText ? `${imageText}
` : ""}`;
}
async function changedLockfiles(deps, wd, baseSha) {
  const tree = await findLockfileTree(wd, deps.fs);
  const out = tree.symlinks.map((l) => l.path);
  for (const rel of tree.files) {
    if (await fileAtCommit(deps, wd, baseSha, rel) !== await deps.fs.readFile(join5(wd, rel))) out.push(rel);
  }
  return out.map(safe5);
}
async function run3({ deps, inputs }) {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.githubToken);
  const stop = (msg) => {
    setOutput("result", "fail", env);
    return fail(msg);
  };
  if (env.GITHUB_EVENT_NAME !== "pull_request") return stop(`scan runs on pull_request events, not ${env.GITHUB_EVENT_NAME ?? "(none)"}`);
  let payload;
  try {
    payload = await readPayload(deps);
  } catch (e) {
    return stop(e.message);
  }
  const n = payload.pull_request?.number;
  if (typeof n !== "number") return stop("event payload has no pull_request.number");
  const baseSha = payload.pull_request?.base?.sha ?? "";
  if (!SHA_RE.test(baseSha)) return stop("event payload has no valid pull_request.base.sha");
  const wd = inputs.workingDirectory;
  if (!inputs.token) {
    if (!isForkPr(payload)) return stop("token is required on pull requests (ci token)");
    try {
      const changed = await changedLockfiles(deps, wd, baseSha);
      if (changed.length) return stop(`fork changes lockfiles (${changed.join(", ")}); push the branch to this repo to scan it`);
      const df = await changedDockerfiles(deps, wd, baseSha);
      const touched = [...df.changed, ...df.symlinks].map(safe5);
      if (touched.length) return stop(`fork changes Dockerfiles (${touched.join(", ")}); push the branch to this repo to scan it`);
    } catch (e) {
      return stop(`decant scan: ${e.message}`);
    }
    notice("fork PR changes no lockfile or Dockerfile; nothing to scan");
    setOutput("result", "pass", env);
    return 0;
  }
  if (!inputs.githubToken) return stop("github-token is required");
  if (!SEVERITIES.includes(inputs.failOn)) return stop(`fail-on must be one of ${SEVERITIES.join(", ")}`);
  const failOn = inputs.failOn;
  let cooldownDays = 7;
  const policyFile = join5(wd, inputs.policyPath);
  if (await deps.fs.exists(policyFile)) {
    let parsed;
    try {
      parsed = parsePolicy(JSON.parse(await deps.fs.readFile(policyFile)));
    } catch (e) {
      return stop(`${policyFile} is not valid JSON: ${e.message}`);
    }
    if (!parsed.ok) return stop(`invalid policy:
${parsed.errors.map((m) => `- ${m}`).join("\n")}`);
    cooldownDays = parsed.policy.cooldownDays;
  }
  const ref = `pr-${n}`;
  const gh = github(deps.fetch, inputs.githubToken, env.GITHUB_REPOSITORY ?? "", {
    selfLogin: env.DECANT_GITHUB_LOGIN || "github-actions[bot]"
  });
  try {
    if (newReviewScope(payload)) {
      const hit = (await gh.prLabels(n)).find((l) => l.toLowerCase() === REVIEWED);
      if (hit) {
        await gh.removeLabel(n, hit);
        notice(`${payload.action === "synchronize" ? "new commits" : payload.action === "reopened" ? "reopened" : "base changed"}: ${REVIEWED} removed; re-review required`);
      }
    }
    const added = [];
    const withDecantUrls = [];
    const tree = await findLockfileTree(wd, deps.fs);
    if (tree.symlinks.length) {
      for (const l of tree.symlinks) {
        const msg = `${join5(wd, l.path)}: ${l.dir ? "symlinked directory" : "lockfile is a symlink"}; not supported`;
        error(msg);
        process.stderr.write(`${msg}
`);
      }
      return stop(`${tree.symlinks.length} symlink(s) in ${wd}; decant does not scan through symlinks`);
    }
    for (const rel of tree.files) {
      const abs = join5(wd, rel);
      const head = await deps.fs.readFile(abs);
      const base = await fileAtCommit(deps, wd, baseSha, rel);
      if (base === head) continue;
      if (isPackageLock2(rel) && containsDecantUrls(head, inputs.decantUrl)) {
        withDecantUrls.push(abs);
        continue;
      }
      let headDeps;
      try {
        headDeps = parseLock(rel, head, inputs.decantUrl);
      } catch (e) {
        return stop(`${abs}: ${e.message}`);
      }
      let baseDeps = [];
      try {
        if (base !== null) baseDeps = parseLock(rel, base, inputs.decantUrl);
      } catch {
      }
      added.push(...diffDeps(baseDeps, headDeps));
    }
    if (withDecantUrls.length) {
      const url = inputs.decantUrl.replace(/\/+$/, "");
      for (const f of withDecantUrls) {
        error(`${f} contains decant URLs`, f);
        const q = shellQuote(f);
        const qb = shellQuote(`${f}.bak`);
        process.stderr.write(`${f} contains decant URLs; run: sed -i.bak -E 's#${url}(/r/[^/]+)?/npm/#https://registry.npmjs.org/#g' ${q} && rm ${qb}
`);
      }
      setOutput("result", "fail", env);
      return 1;
    }
    const registry = /* @__PURE__ */ new Map();
    const rows = [];
    const row = (dep) => ({ dep, osv: "\u2014", guarddog: "\u2014", vulns: [], problems: [], notes: [], warn: false, flagged: false, findings: [] });
    for (const d of added) {
      if (d.source === "registry") {
        if (!registry.has(formatPackageId(d))) registry.set(formatPackageId(d), d);
        continue;
      }
      const r = row(d);
      if (d.mismatch) r.problems.push("resolved URL does not match package");
      else {
        r.warn = true;
        r.notes.push("not from the registry; not scanned");
        warning(`${safe5(d.name)}@${safe5(d.version)} in ${d.file} is not from the registry and was not scanned`, d.file);
      }
      rows.push(r);
    }
    if (registry.size > MAX_DEPS2) return stop(`too many new dependencies (${registry.size}); split the change`);
    const regDeps = [...registry.values()];
    const vulnsByKey = regDeps.length ? await createOsv(deps.fetch).queryVulns(regDeps) : /* @__PURE__ */ new Map();
    const client = decant(deps.fetch, inputs.decantUrl, inputs.token, { sleep: deps.sleep });
    const scratch = `${env.RUNNER_TEMP || tmpdir2()}/decant-scan`;
    let gd = null;
    const guarddog = () => {
      gd ??= installGuardDog(deps.exec, deps.fs.readFile, `${env.RUNNER_TEMP || tmpdir2()}/decant-guarddog`, actionDir(env.GITHUB_ACTION_PATH), env);
      return gd;
    };
    if (regDeps.length) await deps.fs.mkdir(scratch);
    const blocked = new Set(regDeps.length ? (await client.blocks()).map((b) => b.package) : []);
    const regRows = regDeps.map(row);
    await pool(regRows, CONCURRENCY2, async (r, i) => {
      try {
        await evaluate(r, i);
      } catch (e) {
        const msg = e.message;
        error(`${safe5(r.dep.name)}@${safe5(r.dep.version)}: ${msg}`);
        r.problems.push("scan error (see log)");
      }
    });
    async function evaluate(r, i) {
      const d = r.dep;
      const id = formatPackageId(d);
      const problem = (p) => {
        if (!r.problems.includes(p)) r.problems.push(p);
      };
      if (blocked.has(id)) problem("blocked by decant");
      const cached = await client.getVerdicts(id);
      const of = (s) => cached.find((v) => v.scanner === s);
      if (cached.some((v) => v.result === "malicious")) r.problems.push(`malicious (${cached.filter((v) => v.result === "malicious").map((v) => safe5(v.scanner)).join(", ")})`);
      r.vulns = vulnsByKey.get(depKey(d)) ?? [];
      const mal = r.vulns.filter((v) => v.malicious).map((v) => v.id);
      const osvResult = mal.length ? "malicious" : "clean";
      const cOsv = of("osv");
      if (!cOsv || RESULT_RANK[osvResult] > RESULT_RANK[cOsv.result]) {
        await client.putVerdict({ package: id, scanner: "osv", scannerVersion: OSV_SCANNER_VERSION, result: osvResult, details: mal.length ? { malicious: mal } : void 0 });
      }
      const osvWorst = cOsv && RESULT_RANK[cOsv.result] > RESULT_RANK[osvResult] ? cOsv.result : osvResult;
      r.osv = osvWorst;
      if (osvResult === "malicious" && !r.problems.some((p) => p.startsWith("malicious"))) r.problems.push("malicious (osv)");
      const bad = r.vulns.filter((v) => !v.malicious && SEV_RANK[v.severity] >= SEV_RANK[failOn]);
      if (bad.length) r.problems.push(`vulnerable (\u2265 ${failOn})`);
      const unavailable = async (status) => {
        if (status === "cooldown") problem(await cooldownNote(deps, d, cooldownDays));
        else problem(status === "blocked" ? "blocked by decant" : "not found in decant");
      };
      const cGd = of("guarddog");
      let gdResult = null;
      if (cGd) {
        gdResult = cGd.result;
        r.guarddog = `${cGd.result} (cached)`;
        r.findings = normalizeFindings(cGd.details);
        const status = await client.availability(d.eco, d.name, d.version, ref);
        if (status !== "ok") await unavailable(status);
      } else {
        const dl = d.eco === "npm" ? await client.downloadNpm(d.name, d.version, ref) : await client.downloadGo(d.name, d.version, ref);
        if (dl.status !== "ok") {
          await unavailable(dl.status);
        } else {
          const path = `${scratch}/${i}.${d.eco === "npm" ? "tgz" : "zip"}`;
          await deps.fs.writeBytes(path, dl.bytes);
          const { bin } = await guarddog();
          const res = d.eco === "npm" ? await scanNpm(deps.exec, bin, path) : await scanGo(deps.exec, bin, path);
          await client.putVerdict({ package: id, scanner: "guarddog", scannerVersion: GUARDDOG_VERSION, result: res.result, details: res.details });
          gdResult = res.result;
          r.guarddog = res.result;
          r.findings = res.details;
        }
      }
      if (gdResult !== "clean" && r.findings.length) r.notes.push(`GuardDog: ${r.findings.map((f) => `${safe5(f.rule)}${count(f)}`).join(", ")}`);
      if (gdResult === "flagged") r.flagged = true;
    }
    const gate = await dockerGate({ deps, wd, baseSha, ref, client });
    if (gate.fatal) return stop(gate.fatal);
    const imageRows = gate.rows;
    let imageNote = "";
    if (imageRows.length) {
      const others = await otherImageFiles(deps, wd);
      if (others.length) imageNote = `Images referenced in ${others.slice(0, 5).map((f) => `\`${safe5(f)}\``).join(", ")}${others.length > 5 ? ", \u2026" : ""} are not gated (Dockerfiles only).`;
    }
    const anyFlagged = regRows.some((r) => r.flagged);
    const reviewed = anyFlagged ? await gh.labelAddedByWriter(n, REVIEWED) : false;
    for (const r of regRows) {
      if (!r.flagged) continue;
      const what = r.findings.length ? r.findings.map(findingText).join("; ") : "no rule details recorded";
      warning(`${safe5(r.dep.name)}@${safe5(r.dep.version)} flagged by GuardDog: ${what}`);
      if (reviewed) r.notes.unshift(`flagged; ${REVIEWED} by a writer`);
      else r.problems.push(`flagged by GuardDog (needs ${REVIEWED} from a writer)`);
    }
    let securityNote = "";
    if (anyFlagged && (await gh.prLabels(n)).some((l) => l.toLowerCase() === SECURITY)) {
      const pr = await gh.getPr(n);
      if (pr.autoMerge) {
        await gh.disableAutoMerge(pr.nodeId);
        notice("flagged security PR: auto-merge disabled; merge it manually after review");
      }
      securityNote = `**Auto-merge is off:** a dependency was flagged by GuardDog, so this \`${SECURITY}\` PR must be merged manually after review.`;
    }
    const all = [...regRows, ...rows];
    const pass = all.every((r) => r.problems.length === 0) && imageRows.every((r) => r.problems.length === 0);
    setOutput("result", pass ? "pass" : "fail", env);
    setOutput("flagged", anyFlagged ? "true" : "false", env);
    if (all.length === 0 && imageRows.length === 0) {
      const body = `${MARKER}
## decant scan: \u2705 pass

No new dependency versions.`;
      appendSummary(body, env);
      await gh.updateComment(n, MARKER, body);
      return 0;
    }
    const note = [securityNote, imageNote].filter(Boolean).join("\n\n");
    appendSummary(render(all, pass, failOn, ref, Infinity, note, imageRows), env);
    await gh.upsertComment(n, MARKER, render(all, pass, failOn, ref, COMMENT_LIMIT, note, imageRows));
    if (!pass) {
      const deps2 = all.filter((r) => r.problems.length).length;
      const imgs = imageRows.filter((r) => r.problems.length).length;
      return fail(`decant scan failed: ${[deps2 ? `${deps2} dependency version(s)` : "", imgs ? `${imgs} base image(s)` : ""].filter(Boolean).join(" and ")} need attention`);
    }
    return 0;
  } catch (e) {
    return stop(`decant scan: ${e.message}`);
  }
}

// action/src/modes/setup.ts
var setup_exports = {};
__export(setup_exports, {
  run: () => run4
});
function fail2(msg) {
  error(msg);
  process.stderr.write(`${msg}
`);
  return 1;
}
async function run4({ deps, inputs }) {
  mask(inputs.token);
  const env = deps.env;
  const home = env.HOME;
  if (!home) return fail2("HOME is not set");
  const npmrc = `${home}/.npmrc`;
  const netrc = `${home}/.netrc`;
  if (inputs.bypass) {
    const reason = inputs.bypassReason.trim();
    if (!reason) return fail2("bypass requires bypass-reason");
    await deps.fs.writeFile(npmrc, "registry=https://registry.npmjs.org/\nignore-scripts=true\n");
    exportVar("GOPROXY", "https://proxy.golang.org", env);
    exportVar("npm_config_registry", "https://registry.npmjs.org/", env);
    exportVar("npm_config_ignore_scripts", "true", env);
    const actor = env.GITHUB_ACTOR ?? "";
    warning(`decant BYPASSED by ${actor}: ${reason}`);
    const runUrl = `${env.GITHUB_SERVER_URL ?? ""}/${env.GITHUB_REPOSITORY ?? ""}/actions/runs/${env.GITHUB_RUN_ID ?? ""}`;
    appendSummary(`## \u26A0\uFE0F decant bypassed

Actor: ${actor} \xB7 Reason: ${reason} \xB7 Run: ${runUrl}`, env);
    return 0;
  }
  if (!inputs.token) return fail2("token is required (read token)");
  const origin = inputs.decantUrl.replace(/\/+$/, "");
  const host = new URL(origin).host;
  let prefix = "";
  if (env.GITHUB_EVENT_NAME === "pull_request") {
    let payload;
    try {
      payload = await readPayload(deps);
    } catch (e) {
      return fail2(e.message);
    }
    const n = payload.pull_request?.number;
    if (typeof n !== "number") return fail2("event payload has no pull_request.number");
    if (!isForkPr(payload)) prefix = `/r/pr-${n}`;
  }
  const base = `${origin}${prefix}`;
  const npmPath = new URL(`${base}/npm/`).pathname;
  await deps.fs.writeFile(npmrc, `registry=${base}/npm/
//${host}${npmPath}:_authToken=${inputs.token}
ignore-scripts=true
`, 384);
  await deps.fs.writeFile(netrc, `machine ${host} login decant password ${inputs.token}
`, 384);
  await deps.fs.chmod(npmrc, 384);
  await deps.fs.chmod(netrc, 384);
  exportVar("GOPROXY", `${base}/go`, env);
  exportVar("npm_config_registry", `${base}/npm/`, env);
  exportVar("npm_config_ignore_scripts", "true", env);
  return 0;
}

// action/src/modes/sync.ts
var sync_exports = {};
__export(sync_exports, {
  overlayPolicy: () => overlayPolicy,
  run: () => run5
});
import { join as join6 } from "node:path";

// action/src/dep-summary.ts
var MAX_VIA = 5;
var MAX_SUMMARY_BYTES = 1024 * 1024;
var DEP_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies"];
var ROOT_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
var NM = "node_modules/";
function nameOf(key2, e) {
  return e.name ?? key2.slice(key2.lastIndexOf(NM) + NM.length);
}
function resolve3(packages, from, dep) {
  let dir = from;
  for (; ; ) {
    const candidate = dir === "" ? `${NM}${dep}` : `${dir}/${NM}${dep}`;
    if (packages[candidate]) return candidate;
    if (dir === "") return null;
    const i = dir.lastIndexOf("/");
    dir = i < 0 ? "" : dir.slice(0, i);
  }
}
function target(packages, key2) {
  const e = packages[key2];
  if (!e) return null;
  if (e.link) return e.resolved !== void 0 && packages[e.resolved] ? e.resolved : null;
  return key2;
}
var byName = (a, b) => a < b ? -1 : a > b ? 1 : 0;
function summarizePackageLock(text) {
  const lock = JSON.parse(text);
  if (!lock.packages || (lock.lockfileVersion ?? 1) < 2) throw new Error("regenerate package-lock.json with npm 7 or newer");
  const packages = lock.packages;
  const root = packages[""] ?? {};
  const rootDeps = /* @__PURE__ */ new Set();
  for (const f of ROOT_FIELDS) for (const d of Object.keys(root[f] ?? {})) rootDeps.add(d);
  function declared(from, names, into) {
    for (const d of names) {
      const k = resolve3(packages, from, d);
      const t = k === null ? null : target(packages, k);
      if (k !== null && t !== null && !into.has(t)) into.set(t, packages[k].link ? nameOf(k, packages[k]) : nameOf(t, packages[t]));
    }
  }
  const directKeys = /* @__PURE__ */ new Map();
  declared("", rootDeps, directKeys);
  const roots = new Map(directKeys);
  for (const e of Object.values(packages)) {
    if (!e.link || e.resolved === void 0) continue;
    const ws = packages[e.resolved];
    if (!ws) continue;
    const names = /* @__PURE__ */ new Set();
    for (const f of ROOT_FIELDS) for (const d of Object.keys(ws[f] ?? {})) names.add(d);
    declared(e.resolved, names, roots);
  }
  const via = /* @__PURE__ */ new Map();
  for (const [start, directName] of roots) {
    const seen = /* @__PURE__ */ new Set([start]);
    const queue = [start];
    for (let qi = 0; qi < queue.length; qi++) {
      const at = queue[qi];
      const e = packages[at];
      for (const f of DEP_FIELDS) {
        for (const d of Object.keys(e[f] ?? {})) {
          const k = resolve3(packages, at, d);
          const t = k === null ? null : target(packages, k);
          if (t === null || seen.has(t)) continue;
          seen.add(t);
          queue.push(t);
          let s = via.get(t);
          if (!s) via.set(t, s = /* @__PURE__ */ new Set());
          s.add(directName);
        }
      }
    }
  }
  const out = [];
  for (const [key2, e] of Object.entries(packages)) {
    if (key2 === "" || e.link || e.inBundle || !key2.includes(NM) || !e.version) continue;
    const name = nameOf(key2, e);
    const direct = directKeys.has(key2);
    const parents = [...via.get(key2) ?? []].filter((n) => !(direct && n === name)).sort(byName);
    out.push({ eco: "npm", name, version: e.version, direct, via: parents.slice(0, MAX_VIA) });
  }
  return out;
}
function goDirect(goMod) {
  const out = /* @__PURE__ */ new Map();
  let inBlock = false;
  for (const raw of goMod.split(/\r?\n/)) {
    const line2 = raw.trim();
    let spec = null;
    if (inBlock) {
      if (line2.startsWith(")")) inBlock = false;
      else spec = line2;
    } else if (/^require\s*\($/.test(line2)) {
      inBlock = true;
    } else if (/^require\s+/.test(line2)) {
      spec = line2.replace(/^require\s+/, "");
    }
    if (!spec || spec.startsWith("//")) continue;
    const comment = spec.indexOf("//");
    const indirect = comment >= 0 && /^\/\/\s*indirect\b/.test(spec.slice(comment));
    const parts = (comment >= 0 ? spec.slice(0, comment) : spec).trim().split(/\s+/);
    if (parts.length !== 2 || indirect) continue;
    out.set(parts[0].replace(/^"|"$/g, ""), parts[1]);
  }
  return out;
}
function summarizeGo(goSum, goMod) {
  const direct = goMod === null ? /* @__PURE__ */ new Map() : goDirect(goMod);
  return parseGoSum(goSum, "go.sum").map((d) => ({ eco: "go", name: d.name, version: d.version, direct: direct.get(d.name) === d.version, via: [] }));
}
function merge(into, deps) {
  for (const d of deps) {
    const k = `${d.eco}\0${d.name}\0${d.version}`;
    const cur = into.get(k);
    if (!cur) {
      into.set(k, { ...d, via: [...d.via] });
      continue;
    }
    cur.direct ||= d.direct;
    cur.via = [.../* @__PURE__ */ new Set([...cur.via, ...d.via])].sort(byName).slice(0, MAX_VIA);
  }
}
async function dependencySummary(root, fs) {
  const base = root.replace(/\/+$/, "");
  const tree = await findLockfileTree(base, fs);
  const all = /* @__PURE__ */ new Map();
  const warnings = [];
  for (const rel of tree.files) {
    const abs = `${base}/${rel}`;
    try {
      if (rel.endsWith("go.sum")) {
        const modPath = `${abs.slice(0, -"go.sum".length)}go.mod`;
        const goMod = await fs.exists(modPath) ? await fs.readFile(modPath) : null;
        merge(all, summarizeGo(await fs.readFile(abs), goMod));
      } else {
        merge(all, summarizePackageLock(await fs.readFile(abs)));
      }
    } catch (e) {
      warnings.push(`${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const deps = [...all.values()].sort((a, b) => byName(a.eco, b.eco) || byName(a.name, b.name) || byName(a.version, b.version));
  return { deps, warnings };
}
var size = (sha, deps) => Buffer.byteLength(JSON.stringify({ sha, deps }));
function capSummary(sha, deps) {
  if (size(sha, deps) <= MAX_SUMMARY_BYTES) return { deps, trimmed: null };
  const noVia = deps.map((d) => ({ ...d, via: [] }));
  if (size(sha, noVia) <= MAX_SUMMARY_BYTES) return { deps: noVia, trimmed: "via" };
  return { deps: noVia.filter((d) => d.direct), trimmed: "transitive" };
}

// action/src/modes/sync.ts
function fail3(msg) {
  error(msg);
  process.stderr.write(`${msg}
`);
  return 1;
}
function overlayPolicy(baseRaw, base, prRaw, pr) {
  const baseAllow = new Set(base.allow.map((a) => a.package));
  const baseBlock = new Set(base.block.map((b) => b.package));
  const prBlock = new Set(pr.block.map((b) => b.package));
  const prAllowRaw = prRaw.allow ?? [];
  const prBlockRaw = prRaw.block ?? [];
  const allow = [...baseRaw.allow ?? [], ...prAllowRaw.filter((_, i) => !baseAllow.has(pr.allow[i].package))];
  const block = [...baseRaw.block ?? [], ...prBlockRaw.filter((_, i) => !baseBlock.has(pr.block[i].package))];
  const changed = pr.cooldownDays !== base.cooldownDays || JSON.stringify(pr.autoShip) !== JSON.stringify(base.autoShip) || base.block.some((b) => !prBlock.has(b.package));
  return { raw: { ...baseRaw, allow, block }, changed };
}
function parseRaw(text) {
  try {
    const raw = JSON.parse(text);
    const p = parsePolicy(raw);
    return p.ok ? { raw, policy: p.policy } : null;
  } catch {
    return null;
  }
}
function errorText2(b) {
  return typeof b === "object" && b !== null && typeof b.error === "string" ? b.error : typeof b === "string" ? b : JSON.stringify(b);
}
var REPO_RE = /^[A-Za-z0-9-]+\/(?!\.\.?$)[A-Za-z0-9._-]+$/;
async function sendDependencySummary(deps, client, wd, project, sha) {
  try {
    const s = await dependencySummary(wd, deps.fs);
    for (const w of s.warnings) warning(`dependency summary: ${w}`);
    const c = capSummary(sha, s.deps);
    if (c.trimmed === "via") warning("dependency summary is over 1 MB; sent without the held-back-by names");
    if (c.trimmed === "transitive") warning("dependency summary is over 1 MB; sent direct dependencies only");
    const repo = deps.env.GITHUB_REPOSITORY ?? "";
    const res = await client.syncDeps(project, sha, c.deps, REPO_RE.test(repo) ? repo : void 0);
    if (res.status < 200 || res.status >= 300) warning(`decant did not store the dependency summary (HTTP ${res.status}): ${errorText2(res.body)}`);
  } catch (e) {
    warning(`dependency summary not sent: ${e instanceof Error ? e.message : String(e)}`);
  }
}
var MAX_IMAGES2 = 200;
var safe6 = (s) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, "?");
async function sendImages(deps, client, wd, ref) {
  try {
    const tree = await findDockerfiles(wd, deps.fs);
    const byKey = /* @__PURE__ */ new Map();
    let unpinned = 0;
    for (const rel of tree.files) {
      const p = parseDockerfile(await deps.fs.readFile(join6(wd, rel)));
      if (p.errors.length) warning(`${safe6(rel)}: ${p.errors.length} line(s) decant cannot read; the PR scan fails on them`);
      for (const f of p.froms) {
        if (f.kind !== "image" || !f.ref) continue;
        if (!f.ref.digest) {
          unpinned++;
          continue;
        }
        const k = `${f.ref.name}@${f.ref.digest}`;
        const cur = byKey.get(k) ?? { name: f.ref.name, digest: f.ref.digest, files: [] };
        if (!cur.files.includes(rel) && cur.files.length < 20) cur.files.push(rel);
        byKey.set(k, cur);
      }
    }
    if (unpinned) warning(`${unpinned} base image(s) on the default branch are not pinned by digest; see docs/adopt.md`);
    let images = [...byKey.values()];
    if (images.length > MAX_IMAGES2) {
      warning(`${images.length} base images; reporting the first ${MAX_IMAGES2}`);
      images = images.slice(0, MAX_IMAGES2);
    }
    const r = await client.images(ref, images, { main: true });
    const waiting = r.images.filter((i) => i.clock === "unverified");
    if (waiting.length) warning(`decant could not verify ${waiting.length} image digest(s) in the registry yet: ${waiting.slice(0, 5).map((i) => safe6(`${i.name}@${i.digest.slice(0, 19)}`)).join(", ")}`);
  } catch (e) {
    warning(`base images not reported: ${e instanceof Error ? e.message : String(e)}`);
  }
}
async function run5({ deps, inputs }) {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.syncToken);
  const policyFile = join6(inputs.workingDirectory, inputs.policyPath);
  if (!await deps.fs.exists(policyFile)) return fail3(`decant.json not found at ${policyFile}`);
  let raw;
  try {
    raw = JSON.parse(await deps.fs.readFile(policyFile));
  } catch (e) {
    return fail3(`${policyFile} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
  const parsed = parsePolicy(raw);
  if (!parsed.ok) return fail3(`invalid policy:
${parsed.errors.map((m) => `- ${m}`).join("\n")}`);
  let payload;
  try {
    payload = await readPayload(deps);
  } catch (e) {
    return fail3(e.message);
  }
  const event = env.GITHUB_EVENT_NAME ?? "";
  let ref;
  let token;
  let policy = parsed.policy;
  if (event === "pull_request") {
    const n = payload.pull_request?.number;
    if (typeof n !== "number") return fail3("event payload has no pull_request.number");
    ref = `pr-${n}`;
    token = inputs.token;
    if (!token) {
      if (isForkPr(payload)) {
        notice("fork PR has no secrets; decant sync skipped");
        return 0;
      }
      return fail3("token is required on pull requests");
    }
    const baseSha = payload.pull_request?.base?.sha ?? "";
    if (!SHA_RE.test(baseSha)) return fail3("event payload has no valid pull_request.base.sha");
    let baseText;
    try {
      baseText = await fileAtCommit(deps, inputs.workingDirectory, baseSha, inputs.policyPath);
    } catch (e) {
      return fail3(e.message);
    }
    const base = baseText === null ? null : parseRaw(baseText);
    if (baseText !== null && !base) warning(`${inputs.policyPath} at the base commit is invalid; syncing the PR's policy as is`);
    if (base) {
      const o = overlayPolicy(base.raw, base.policy, raw, parsed.policy);
      raw = o.raw;
      policy = base.policy;
      if (o.changed) notice("policy changes in decant.json take effect after merge");
    }
  } else if (event === "push" || event === "workflow_dispatch" || event === "schedule") {
    const branch = payload.repository?.default_branch ?? "";
    if (!branch || env.GITHUB_REF !== `refs/heads/${branch}`) {
      if (event === "workflow_dispatch") return fail3("sync must run on the default branch");
      notice("not the default branch; nothing to sync");
      return 0;
    }
    ref = branch;
    token = inputs.syncToken;
    if (!token) return fail3("sync-token is required on the default branch");
  } else {
    return fail3(`unsupported event ${event}`);
  }
  const project = inputs.project || policy.project;
  const client = decant(deps.fetch, inputs.decantUrl, token, { sleep: deps.sleep });
  const res = await client.syncPolicy(project, raw, env.GITHUB_SHA ?? "", ref);
  if (res.status < 200 || res.status >= 300) return fail3(`decant rejected the policy (HTTP ${res.status}): ${errorText2(res.body)}`);
  if (event !== "pull_request") {
    await sendDependencySummary(deps, client, inputs.workingDirectory, project, env.GITHUB_SHA ?? "");
    await sendImages(deps, client, inputs.workingDirectory, ref);
  }
  setOutput("ref", ref, env);
  return 0;
}

// action/src/main.ts
var modes = { setup: setup_exports, sync: sync_exports, scan: scan_exports, audit: audit_exports, adopt: adopt_exports };
async function run6(deps) {
  const inputs = readInputs(deps.env);
  const mode = Object.hasOwn(modes, inputs.mode) ? modes[inputs.mode] : void 0;
  if (!mode) {
    const msg = `unknown mode ${inputs.mode}`;
    error(msg);
    process.stderr.write(`${msg}
`);
    return 1;
  }
  return mode.run({ deps, inputs });
}

// action/src/entry.ts
run6(defaultDeps()).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    error(e instanceof Error ? e.message : String(e));
    process.exitCode = 1;
  }
);
