var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// action/src/deps.ts
import * as nodeFs from "node:fs/promises";

// action/src/exec.ts
import { spawn } from "node:child_process";
var defaultExec = (cmd, args, opts = {}) => new Promise((resolve) => {
  const child = spawn(cmd, args, {
    cwd: opts.cwd,
    env: opts.env ? { ...process.env, ...opts.env } : process.env,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (d) => stdout += d);
  child.stderr.setEncoding("utf8").on("data", (d) => stderr += d);
  child.on("error", (e) => resolve({ code: 127, stdout, stderr: stderr + String(e.message) }));
  child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  child.stdin.on("error", () => {
  });
  child.stdin.end(opts.input ?? "");
});

// action/src/deps.ts
var defaultFs = {
  readFile: (p) => nodeFs.readFile(p, "utf8"),
  writeFile: (p, data, mode) => nodeFs.writeFile(p, data, mode === void 0 ? void 0 : { mode }),
  async readdir(p) {
    const entries = await nodeFs.readdir(p, { withFileTypes: true });
    return entries.map((e) => ({ name: e.name, isDir: e.isDirectory(), isSymlink: e.isSymbolicLink() }));
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

// action/src/modes/stub.ts
async function notImplemented(_ctx) {
  process.stderr.write("not implemented\n");
  return 1;
}

// action/src/modes/adopt.ts
var run = (ctx) => notImplemented(ctx);

// action/src/modes/audit.ts
var audit_exports = {};
__export(audit_exports, {
  run: () => run2
});
var run2 = (ctx) => notImplemented(ctx);

// action/src/modes/scan.ts
var scan_exports = {};
__export(scan_exports, {
  run: () => run3
});
var run3 = (ctx) => notImplemented(ctx);

// action/src/modes/setup.ts
var setup_exports = {};
__export(setup_exports, {
  run: () => run4
});
function fail(msg) {
  error(msg);
  process.stderr.write(`${msg}
`);
  return 1;
}
async function run4({ deps, inputs }) {
  mask(inputs.token);
  const env = deps.env;
  const home = env.HOME;
  if (!home) return fail("HOME is not set");
  const npmrc = `${home}/.npmrc`;
  const netrc = `${home}/.netrc`;
  if (inputs.bypass) {
    const reason = inputs.bypassReason.trim();
    if (!reason) return fail("bypass requires bypass-reason");
    await deps.fs.writeFile(npmrc, "registry=https://registry.npmjs.org/\nignore-scripts=true\n");
    exportVar("GOPROXY", "https://proxy.golang.org", env);
    const actor = env.GITHUB_ACTOR ?? "";
    warning(`decant BYPASSED by ${actor}: ${reason}`);
    const runUrl = `${env.GITHUB_SERVER_URL ?? ""}/${env.GITHUB_REPOSITORY ?? ""}/actions/runs/${env.GITHUB_RUN_ID ?? ""}`;
    appendSummary(`## \u26A0\uFE0F decant bypassed

Actor: ${actor} \xB7 Reason: ${reason} \xB7 Run: ${runUrl}`, env);
    return 0;
  }
  if (!inputs.token) return fail("token is required (read token)");
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
import { join } from "node:path";

// src/ids.ts
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
  for (const [key, withAdded] of [["allow", true], ["block", false]]) {
    const raw = input[key];
    if (raw === void 0) continue;
    if (!Array.isArray(raw)) {
      errors.push(`${key} must be an array`);
      continue;
    }
    raw.forEach((r, i) => {
      const e = entry(r, `${key}[${i}]`, withAdded, errors);
      if (e) (withAdded ? allow : block).push(e);
    });
  }
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, policy: { project, cooldownDays, autoShip, allow, block } };
}

// src/go/escape.ts
function escapeModulePath(p) {
  return p.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

// action/src/http.ts
var TIMEOUT_MS = 3e4;
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
      const npmBase = `${base}${prefix(ref)}/npm`;
      const metaLabel = `decant GET ${prefix(ref)}/npm/${name}`;
      const meta = await call("GET", `${npmBase}/${npmMetaPath(name)}`, { headers: { accept: "application/json" } });
      if (meta.status === 404) return { status: classify404(await meta.text().catch(() => "")) };
      const doc = await ok(meta, metaLabel);
      const tarball = doc.versions?.[version]?.dist?.tarball;
      let target;
      if (typeof tarball === "string") {
        let u;
        try {
          u = new URL(tarball);
        } catch {
          throw new Error(`${metaLabel}: invalid tarball URL`);
        }
        if (u.origin !== origin) throw new Error(`${metaLabel}: tarball host ${u.host} is not the decant host`);
        target = u.href;
      } else {
        const basename = name.slice(name.lastIndexOf("/") + 1);
        target = `${npmBase}/${name}/-/${basename}-${encodeURIComponent(version)}.tgz`;
      }
      const res = await call("GET", target);
      return bytesOr404(res, `decant GET ${new URL(target).pathname}`);
    },
    /** Fetches `<prefix>/go/<module>/@v/<version>.zip` with Basic decant:<token>. */
    async downloadGo(module, version, ref) {
      const path = `${prefix(ref)}/go/${escapeModulePath(module)}/@v/${escapeModulePath(version)}.zip`;
      const res = await call("GET", path, { headers: { authorization: `Basic ${basic}` } });
      return bytesOr404(res, `decant GET ${path}`);
    }
  };
}

// action/src/modes/sync.ts
function fail2(msg) {
  error(msg);
  process.stderr.write(`${msg}
`);
  return 1;
}
async function run5({ deps, inputs }) {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.syncToken);
  const policyFile = join(inputs.workingDirectory, inputs.policyPath);
  if (!await deps.fs.exists(policyFile)) return fail2(`decant.json not found at ${policyFile}`);
  let raw;
  try {
    raw = JSON.parse(await deps.fs.readFile(policyFile));
  } catch (e) {
    return fail2(`${policyFile} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
  const parsed = parsePolicy(raw);
  if (!parsed.ok) return fail2(`invalid policy:
${parsed.errors.map((m) => `- ${m}`).join("\n")}`);
  let payload = {};
  if (env.GITHUB_EVENT_PATH) {
    try {
      payload = JSON.parse(await deps.fs.readFile(env.GITHUB_EVENT_PATH));
    } catch {
      return fail2(`cannot read event payload at ${env.GITHUB_EVENT_PATH}`);
    }
  }
  const event = env.GITHUB_EVENT_NAME ?? "";
  let ref;
  let token;
  if (event === "pull_request") {
    const n = payload.pull_request?.number;
    if (typeof n !== "number") return fail2("event payload has no pull_request.number");
    ref = `pr-${n}`;
    token = inputs.token;
    if (!token) {
      const head = payload.pull_request?.head?.repo;
      const fork = !head || head.full_name !== payload.repository?.full_name;
      if (fork) {
        notice("fork PR has no secrets; decant sync skipped");
        return 0;
      }
      return fail2("token is required on pull requests");
    }
  } else if (event === "push") {
    const branch = env.GITHUB_REF_NAME || (env.GITHUB_REF ?? "").replace(/^refs\/heads\//, "");
    if (!branch || branch !== payload.repository?.default_branch) {
      notice("not the default branch; nothing to sync");
      return 0;
    }
    ref = branch;
    token = inputs.syncToken;
    if (!token) return fail2("sync-token is required on the default branch");
  } else {
    return fail2(`unsupported event ${event}`);
  }
  const project = inputs.project || parsed.policy.project;
  const res = await decant(deps.fetch, inputs.decantUrl, token).syncPolicy(project, raw, env.GITHUB_SHA ?? "", ref);
  if (res.status < 200 || res.status >= 300) {
    const b = res.body;
    const msg = typeof b === "object" && b !== null && typeof b.error === "string" ? b.error : typeof b === "string" ? b : JSON.stringify(b);
    return fail2(`decant rejected the policy (HTTP ${res.status}): ${msg}`);
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
