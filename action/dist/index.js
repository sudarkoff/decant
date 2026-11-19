var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
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
var defaultExec = (cmd, args, opts = {}) => new Promise((resolve2) => {
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
  child.on("error", (e) => resolve2({ code: 127, stdout, stderr: stderr + String(e.message) }));
  child.on("close", (code) => resolve2({ code: code ?? 1, stdout, stderr }));
  child.stdin.on("error", () => {
  });
  child.stdin.end(opts.input ?? "");
});

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
    fs: defaultFs
  };
}

// action/src/gh-io.ts
import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
function getInput(name, env = process.env) {
  return (env[`INPUT_${name.replace(/-/g, "_").toUpperCase()}`] ?? "").trim();
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
  if (eco !== "npm" && eco !== "go") return null;
  const rest = id.slice(colon + 1);
  const at = rest.lastIndexOf("@");
  if (at <= 0 || at === rest.length - 1) return null;
  return { eco, name: rest.slice(0, at), version: rest.slice(at + 1) };
}

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
  if (typeof raw.package !== "string" || parsePackageId(raw.package) === null) errors.push(`${path}.package must be a package ID like npm:name@1.0.0`);
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
    const name = e?.name;
    const why = name === "TimeoutError" || name === "AbortError" ? `timed out after ${o.timeoutMs / 1e3}s` : String(e?.message ?? e);
    throw new Error(redact(`${o.label}: ${why}`, o.secrets ?? []));
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
    labels: (p.labels ?? []).map((l) => l.name),
    headRef: p.head.ref,
    headSha: p.head.sha,
    baseRef: p.base.ref,
    baseSha: p.base.sha
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
  return {
    graphql,
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
    /** Head commit sha of branch `name`. */
    async branchHead(name) {
      const r = await json("GET", `${R}/git/ref/heads/${name.split("/").map(encodeURIComponent).join("/")}`);
      return r.object.sha;
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
    /**
     * Updates the body of our open issue titled exactly `title`, else creates it with `labels`.
     * Matches on title and author only (not labels), so a removed label never causes a duplicate.
     */
    async upsertIssue(title, body, labels) {
      const match = (i2) => i2.pull_request === void 0 && i2.title === title && isMine(i2.user);
      const list = `${R}/issues?state=open&per_page=100`;
      const queries = opts.selfLogin ? [`${list}&creator=${encodeURIComponent(opts.selfLogin)}`] : labels.length ? [`${list}&labels=${encodeURIComponent(labels.join(","))}`, list] : [list];
      let hit = null;
      for (const q of queries) {
        const r = await findPaged(q, match);
        if (r.capped) warning(`decant: more than ${MAX_PAGES} pages of open issues; may create a duplicate of "${title}"`);
        if (hit = r.hit) break;
      }
      if (hit) {
        await rest("PATCH", `${R}/issues/${hit.number}`, { body });
        return { number: hit.number, created: false };
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
  for (const line of text.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
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
    raw = {
      $schema: SCHEMA,
      project: inputs.project || repo.slice(repo.indexOf("/") + 1),
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
    const gh = github(deps.fetch, inputs.githubToken, repo, { selfLogin: env.DECANT_GITHUB_LOGIN || "github-actions[bot]" });
    const open = await gh.findOpenPr(BRANCH);
    let head;
    const base = await gh.defaultBranch();
    if (open) head = open.headSha;
    else {
      head = await gh.branchHead(base);
      await gh.createBranch(BRANCH, head);
    }
    await gh.commitFiles(BRANCH, head, "decant: adopt", files);
    if (open) {
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
  run: () => run2
});

// action/src/modes/stub.ts
async function notImplemented(_ctx) {
  process.stderr.write("not implemented\n");
  return 1;
}

// action/src/modes/audit.ts
var run2 = (ctx) => notImplemented(ctx);

// action/src/modes/scan.ts
var scan_exports = {};
__export(scan_exports, {
  MARKER: () => MARKER,
  run: () => run3
});
import { join as join2 } from "node:path";
import { tmpdir } from "node:os";

// action/src/decant-client.ts
function classify404(body) {
  if (/is not available: in cooldown/.test(body)) return "cooldown";
  if (/is not available: blocked/.test(body)) return "blocked";
  return "missing";
}
function npmMetaPath(name) {
  return name.split("/").map((p) => encodeURIComponent(p).replace(/^%40/, "@")).join("%2f");
}
function decant(f, url, token) {
  const base = url.replace(/\/+$/, "");
  const origin = new URL(base).origin;
  const basic = Buffer.from(`decant:${token}`).toString("base64");
  const secrets = [token, basic];
  const bearer = { authorization: `Bearer ${token}` };
  async function call(method, path, opts = {}) {
    const target = path.startsWith("https://") || path.startsWith("http://") ? path : `${base}${path}`;
    if (new URL(target).origin !== origin) throw new Error(`decant: refusing to send credentials to another host (${new URL(target).host})`);
    const headers = { ...bearer, ...opts.headers };
    let body;
    if (opts.body !== void 0) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    return request(f, target, { method, headers, body }, { label: `decant ${method} ${new URL(target).pathname}`, timeoutMs: TIMEOUT_MS, secrets });
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
      const res = await call("PUT", `/api/projects/${encodeURIComponent(project)}/policy`, { body: { policy: parsed, sha, ref } });
      const text = await res.text();
      let body = text;
      try {
        body = JSON.parse(text);
      } catch {
      }
      return { status: res.status, body };
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
var GUARDDOG_VERSION = "3.2.0";
function tail(s) {
  return s.trim().split("\n").slice(-5).join(" ").slice(0, 500);
}
async function installGuardDog(exec, dir, actionPath) {
  const venv = await exec("python3", ["-m", "venv", dir]);
  if (venv.code !== 0) throw new Error(`python3 -m venv failed: ${tail(venv.stderr)}`);
  const req = `${actionPath.replace(/\/+$/, "")}/guarddog-requirements.txt`;
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
  if (pip.code !== 0) throw new Error(`pip install of GuardDog failed: ${tail(pip.stderr)}`);
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
    details.push(Array.isArray(v) ? `${rule} (${v.length})` : rule);
  }
  if (Array.isArray(doc.risks) && doc.risks.length > 0) {
    const label = typeof doc.risk_score?.label === "string" ? doc.risk_score.label : "unlabelled";
    details.push(`risk: ${label}`);
  }
  return { result: details.length > 0 ? "flagged" : "clean", details };
}
async function scan(exec, bin, eco, path) {
  const r = await exec(bin, [eco, "scan", path, "--output-format", "json", "--sandbox"]);
  if (r.code !== 0) throw new Error(`guarddog ${eco} scan exited ${r.code}: ${tail(r.stderr)}`);
  return parseGuardDogJson(r.stdout);
}
var scanNpm = (exec, bin, tgzPath) => scan(exec, bin, "npm", tgzPath);
var scanGo = (exec, bin, zipPath) => scan(exec, bin, "go", zipPath);

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

// action/src/osv.ts
var OSV = "https://api.osv.dev";
var OSV_ECO = { npm: "npm", go: "Go" };
var BATCH = 1e3;
var MAX_PAGES2 = 10;
var DETAIL_CONCURRENCY = 8;
function depKey(d) {
  return `${d.eco}:${d.name}@${d.version}`;
}
var GHSA_SEVERITY = { CRITICAL: "critical", HIGH: "high", MODERATE: "moderate", MEDIUM: "moderate", LOW: "low" };
var RANK = { unknown: 0, low: 1, moderate: 2, high: 3, critical: 4 };
function maxSeverity(...s) {
  return s.reduce((a, b) => RANK[b] > RANK[a] ? b : a, "unknown");
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
function ownSeverity(r) {
  const sev = r.database_specific?.severity;
  const db = typeof sev === "string" ? GHSA_SEVERITY[sev.toUpperCase()] ?? "unknown" : "unknown";
  const cvss = (r.severity ?? []).filter((x) => x.type === "CVSS_V3" && typeof x.score === "string").map((x) => cvss31BaseScore(x.score)).map((n) => n === null ? "unknown" : scoreSeverity(n));
  return maxSeverity(db, ...cvss);
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
    severity: ownSeverity(r),
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

// action/src/modes/scan.ts
var MARKER = "<!-- decant-scan -->";
var MAX_DEPS2 = 500;
var CONCURRENCY2 = 4;
var REVIEWED = "decant:reviewed";
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
var safe2 = (s) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, "?");
var isPackageLock = (rel) => rel === "package-lock.json" || rel.endsWith("/package-lock.json");
var shellQuote = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
function newReviewScope(p) {
  return p.action === "synchronize" || p.action === "reopened" || p.action === "edited" && !!p.changes?.base;
}
var fmtTime = (d) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
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
async function baseFile(deps, wd, sha, rel) {
  const r = await deps.exec("git", ["show", `${sha}:./${rel}`], { cwd: wd });
  if (r.code === 0) return r.stdout;
  if (/does not exist in|exists on disk, but not in/.test(r.stderr)) return null;
  throw new Error(
    `git show ${sha.slice(0, 12)}:${rel} failed: ${r.stderr.trim().slice(0, 300)} (actions/checkout needs fetch-depth: 0)`
  );
}
function parseLock(rel, text, decantUrl) {
  return isPackageLock(rel) ? parsePackageLock(text, rel, decantUrl) : parseGoSum(text, rel);
}
async function cooldownNote(deps, dep, cooldownDays) {
  try {
    const t = dep.eco === "npm" ? await npmPublishTime(deps.fetch, dep.name, dep.version) : await goPublishTime(deps.fetch, dep.name, dep.version);
    if (t) return `waiting for cooldown until ${fmtTime(new Date(t.getTime() + cooldownDays * 864e5))}`;
  } catch {
  }
  return "waiting for cooldown (publish time unknown)";
}
function render(rows, pass, failOn, ref, limit = Infinity) {
  const head = [
    MARKER,
    `## decant scan: ${pass ? "\u2705 pass" : "\u274C fail"}`,
    "",
    `${rows.length} new dependency version${rows.length === 1 ? "" : "s"} (ref \`${ref}\`, fail-on \`${failOn}\`).`,
    "",
    "| Package | Source | OSV | GuardDog | Vulns | Status |",
    "|---|---|---|---|---|---|"
  ].join("\n");
  const lines = [];
  let size = head.length;
  for (const [i, r] of rows.entries()) {
    const vulns = r.vulns.length ? r.vulns.map((v) => `${safe2(v.id)} (${v.malicious ? "malicious" : v.severity})`).join(", ") : "\u2014";
    const status = r.problems.length ? `\u274C ${r.problems.join("; ")}` : r.warn ? `\u26A0\uFE0F ${r.notes.join("; ")}` : `\u2705 ${r.notes.length ? r.notes.join("; ") : "ok"}`;
    const source = r.dep.source === "registry" ? r.dep.eco : "other";
    const line = `| \`${safe2(r.dep.name)}@${safe2(r.dep.version)}\` | ${source} | ${r.osv} | ${r.guarddog} | ${vulns} | ${status} |`;
    if (size + line.length + 1 > limit) {
      lines.push(`
\u2026 and ${rows.length - i} more (see the job summary).`);
      break;
    }
    lines.push(line);
    size += line.length + 1;
  }
  return `${head}
${lines.join("\n")}
`;
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
  if (!inputs.token) {
    if (isForkPr(payload)) {
      notice("fork PR has no secrets; decant scan skipped");
      return 0;
    }
    return stop("token is required on pull requests (ci token)");
  }
  if (!inputs.githubToken) return stop("github-token is required");
  const baseSha = payload.pull_request?.base?.sha ?? "";
  if (!/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(baseSha)) return stop("event payload has no valid pull_request.base.sha");
  if (!SEVERITIES.includes(inputs.failOn)) return stop(`fail-on must be one of ${SEVERITIES.join(", ")}`);
  const failOn = inputs.failOn;
  const wd = inputs.workingDirectory;
  let cooldownDays = 7;
  const policyFile = join2(wd, inputs.policyPath);
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
        const msg = `${join2(wd, l.path)}: ${l.dir ? "symlinked directory" : "lockfile is a symlink"}; not supported`;
        error(msg);
        process.stderr.write(`${msg}
`);
      }
      return stop(`${tree.symlinks.length} symlink(s) in ${wd}; decant does not scan through symlinks`);
    }
    for (const rel of tree.files) {
      const abs = join2(wd, rel);
      const head = await deps.fs.readFile(abs);
      const base = await baseFile(deps, wd, baseSha, rel);
      if (base === head) continue;
      if (isPackageLock(rel) && containsDecantUrls(head, inputs.decantUrl)) {
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
    const row = (dep) => ({ dep, osv: "\u2014", guarddog: "\u2014", vulns: [], problems: [], notes: [], warn: false, flagged: false });
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
        warning(`${safe2(d.name)}@${safe2(d.version)} in ${d.file} is not from the registry and was not scanned`, d.file);
      }
      rows.push(r);
    }
    if (registry.size > MAX_DEPS2) return stop(`too many new dependencies (${registry.size}); split the change`);
    const regDeps = [...registry.values()];
    const vulnsByKey = regDeps.length ? await createOsv(deps.fetch).queryVulns(regDeps) : /* @__PURE__ */ new Map();
    const client = decant(deps.fetch, inputs.decantUrl, inputs.token);
    const scratch = `${env.RUNNER_TEMP || tmpdir()}/decant-scan`;
    let gd = null;
    const guarddog = () => {
      if (!gd) {
        const actionPath = env.GITHUB_ACTION_PATH;
        gd = actionPath ? installGuardDog(deps.exec, `${env.RUNNER_TEMP || tmpdir()}/decant-guarddog`, actionPath) : Promise.reject(new Error("GITHUB_ACTION_PATH is not set"));
      }
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
        error(`${safe2(r.dep.name)}@${safe2(r.dep.version)}: ${msg}`);
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
      if (cached.some((v) => v.result === "malicious")) r.problems.push(`malicious (${cached.filter((v) => v.result === "malicious").map((v) => safe2(v.scanner)).join(", ")})`);
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
          if (res.details.length) r.notes.push(`GuardDog: ${res.details.map(safe2).join(", ")}`);
        }
      }
      if (gdResult === "flagged") r.flagged = true;
    }
    const anyFlagged = regRows.some((r) => r.flagged);
    const reviewed = anyFlagged ? await gh.labelAddedByWriter(n, REVIEWED) : false;
    for (const r of regRows) {
      if (!r.flagged) continue;
      if (reviewed) r.notes.unshift(`flagged; ${REVIEWED} by a writer`);
      else r.problems.push(`flagged by GuardDog (needs ${REVIEWED} from a writer)`);
    }
    const all = [...regRows, ...rows];
    const pass = all.every((r) => r.problems.length === 0);
    setOutput("result", pass ? "pass" : "fail", env);
    setOutput("flagged", anyFlagged ? "true" : "false", env);
    if (all.length === 0) {
      const body = `${MARKER}
## decant scan: \u2705 pass

No new dependency versions.`;
      appendSummary(body, env);
      await gh.updateComment(n, MARKER, body);
      return 0;
    }
    appendSummary(render(all, pass, failOn, ref), env);
    await gh.upsertComment(n, MARKER, render(all, pass, failOn, ref, COMMENT_LIMIT));
    if (!pass) return fail(`decant scan failed: ${all.filter((r) => r.problems.length).length} dependency version(s) need attention`);
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
    const actor = env.GITHUB_ACTOR ?? "";
    warning(`decant BYPASSED by ${actor}: ${reason}`);
    const runUrl = `${env.GITHUB_SERVER_URL ?? ""}/${env.GITHUB_REPOSITORY ?? ""}/actions/runs/${env.GITHUB_RUN_ID ?? ""}`;
    appendSummary(`## \u26A0\uFE0F decant bypassed

Actor: ${actor} \xB7 Reason: ${reason} \xB7 Run: ${runUrl}`, env);
    return 0;
  }
  if (!inputs.token) return fail2("token is required (read token)");
  const base = inputs.decantUrl.replace(/\/+$/, "");
  const host = new URL(base).host;
  await deps.fs.writeFile(npmrc, `registry=${base}/npm/
//${host}/npm/:_authToken=${inputs.token}
ignore-scripts=true
`, 384);
  await deps.fs.writeFile(netrc, `machine ${host} login decant password ${inputs.token}
`, 384);
  await deps.fs.chmod(npmrc, 384);
  await deps.fs.chmod(netrc, 384);
  exportVar("GOPROXY", `${base}/go`, env);
  return 0;
}

// action/src/modes/sync.ts
var sync_exports = {};
__export(sync_exports, {
  run: () => run5
});
import { join as join3 } from "node:path";
function fail3(msg) {
  error(msg);
  process.stderr.write(`${msg}
`);
  return 1;
}
async function run5({ deps, inputs }) {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.syncToken);
  const policyFile = join3(inputs.workingDirectory, inputs.policyPath);
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
  } else if (event === "push") {
    const branch = env.GITHUB_REF_NAME || (env.GITHUB_REF ?? "").replace(/^refs\/heads\//, "");
    if (!branch || branch !== payload.repository?.default_branch) {
      notice("not the default branch; nothing to sync");
      return 0;
    }
    ref = branch;
    token = inputs.syncToken;
    if (!token) return fail3("sync-token is required on the default branch");
  } else {
    return fail3(`unsupported event ${event}`);
  }
  const project = inputs.project || parsed.policy.project;
  const res = await decant(deps.fetch, inputs.decantUrl, token).syncPolicy(project, raw, env.GITHUB_SHA ?? "", ref);
  if (res.status < 200 || res.status >= 300) {
    const b = res.body;
    const msg = typeof b === "object" && b !== null && typeof b.error === "string" ? b.error : typeof b === "string" ? b : JSON.stringify(b);
    return fail3(`decant rejected the policy (HTTP ${res.status}): ${msg}`);
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
