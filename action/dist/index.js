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
var error = (msg, file) => command("error", msg, file);

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
var run4 = (ctx) => notImplemented(ctx);

// action/src/modes/sync.ts
var sync_exports = {};
__export(sync_exports, {
  run: () => run5
});
var run5 = (ctx) => notImplemented(ctx);

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
