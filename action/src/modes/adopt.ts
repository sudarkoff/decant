import { isAbsolute, join, relative, resolve } from 'node:path';
import { formatPackageId, PROJECT_ID_RE } from '../../../src/ids';
import { parsePolicy } from '../../../src/policy/schema';
import { defaultHeadCheckout } from '../checkout';
import { error, mask, notice, setOutput } from '../gh-io';
import { github } from '../github';
import type { ModeCtx } from '../inputs';
import { findLockfileTree, normalizeLockfile, parseGoSum, parsePackageLock, type Dep } from '../lockfiles';
import { goPublishTime, npmPublishTime } from '../registries';

const BRANCH = 'decant/adopt';
const SCHEMA = 'https://raw.githubusercontent.com/sudarkoff/decant/main/schema/policy.json';
const MAX_DEPS = 5000;
const CONCURRENCY = 8;
const DAY = 86_400_000;

type Entry = { package: string; reason: string; added: string };

const safe = (s: string) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, '?');
const ymd = (d: Date) => d.toISOString().slice(0, 10);

/** The project id adopt writes when none is given: the repo name, lowercased. */
export function defaultProject(repo: string): string {
  return repo.slice(repo.indexOf('/') + 1).toLowerCase();
}

export async function run({ deps, inputs }: ModeCtx): Promise<number> {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.githubToken);
  const stop = (msg: string) => {
    setOutput('result', 'fail', env);
    error(msg);
    process.stderr.write(`${msg}\n`);
    return 1;
  };

  if (!inputs.githubToken) return stop('github-token is required');
  const repo = env.GITHUB_REPOSITORY ?? '';
  const wd = inputs.workingDirectory;
  const policyAbs = join(wd, inputs.policyPath);

  // Paths in the commit are relative to the repository root.
  const root = env.GITHUB_WORKSPACE || (isAbsolute(wd) ? wd : process.cwd());
  const repoPath = (abs: string) => relative(resolve(root), resolve(root, abs)).split('\\').join('/');
  const policyRel = repoPath(policyAbs);
  if (policyRel.startsWith('..')) return stop(`${policyAbs} is outside the repository`);

  // 1. Policy: keep an existing valid one, else start fresh.
  let raw: Record<string, unknown>;
  let cooldownDays = 7;
  let existing: Entry[] = [];
  const hadPolicy = await deps.fs.exists(policyAbs);
  if (hadPolicy) {
    let json: unknown;
    try {
      json = JSON.parse(await deps.fs.readFile(policyAbs));
    } catch (e) {
      return stop(`${policyAbs} is not valid JSON: ${(e as Error).message}`);
    }
    const parsed = parsePolicy(json);
    if (!parsed.ok) return stop(`invalid policy:\n${parsed.errors.map((m) => `- ${m}`).join('\n')}`);
    raw = json as Record<string, unknown>;
    cooldownDays = parsed.policy.cooldownDays;
    existing = parsed.policy.allow;
  } else {
    const project = inputs.project || defaultProject(repo);
    if (!PROJECT_ID_RE.test(project)) {
      return stop(
        `project ${JSON.stringify(project)} is not a valid decant project id (must match ${PROJECT_ID_RE.source}); set the project input to your decant project`,
      );
    }
    raw = {
      $schema: SCHEMA,
      project,
      cooldownDays,
      allow: [],
      block: [],
    };
  }

  // 2. Lockfiles (never through symlinks).
  const tree = await findLockfileTree(wd, deps.fs);
  if (tree.symlinks.length) {
    for (const l of tree.symlinks) {
      const msg = `${join(wd, l.path)}: ${l.dir ? 'symlinked directory' : 'lockfile is a symlink'}; not supported`;
      error(msg);
      process.stderr.write(`${msg}\n`);
    }
    return stop(`${tree.symlinks.length} symlink(s) in ${wd}; decant does not adopt through symlinks`);
  }
  const all: Dep[] = [];
  const changedFiles: { path: string; contents: string }[] = [];
  for (const rel of tree.files) {
    const abs = join(wd, rel);
    const text = await deps.fs.readFile(abs);
    try {
      if (rel.endsWith('package-lock.json')) {
        all.push(...parsePackageLock(text, rel, inputs.decantUrl || undefined));
        const n = inputs.decantUrl ? normalizeLockfile(text, inputs.decantUrl) : { text, changed: 0 };
        if (n.changed > 0) changedFiles.push({ path: repoPath(abs), contents: n.text });
      } else {
        all.push(...parseGoSum(text, rel));
      }
    } catch (e) {
      return stop(`${abs}: ${(e as Error).message}`);
    }
  }

  // 3. Dedupe; split registry from not-gated.
  const have = new Set(existing.map((a) => a.package));
  const todo = new Map<string, Dep>();
  const notGated = new Set<string>();
  for (const d of all) {
    const id = formatPackageId(d);
    if (d.source !== 'registry') {
      notGated.add(id);
      continue;
    }
    if (!have.has(id) && !todo.has(id)) todo.set(id, d);
  }
  if (todo.size > MAX_DEPS) return stop(`too many dependencies to adopt (${todo.size})`);

  // 4. Publish times (fail closed).
  const now = deps.now();
  const items = [...todo];
  const published = new Map<string, Date>();
  const failures: string[] = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, items.length) }, async () => {
      while (next < items.length) {
        const [id, d] = items[next++]!;
        try {
          const t = d.eco === 'npm' ? await npmPublishTime(deps.fetch, d.name, d.version) : await goPublishTime(deps.fetch, d.name, d.version);
          if (!t) failures.push(`${safe(id)}: publish time not found on the public registry`);
          else published.set(id, t);
        } catch (e) {
          failures.push(`${safe(id)}: ${(e as Error).message}`);
        }
      }
    }),
  );
  if (failures.length) return stop(`cannot adopt, publish-time lookup failed:\n${failures.sort().map((m) => `- ${m}`).join('\n')}`);

  const added: { id: string; at: Date }[] = [];
  for (const [id] of items) {
    const at = published.get(id)!;
    if (now.getTime() - at.getTime() < cooldownDays * DAY) added.push({ id, at });
  }
  added.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const today = ymd(now);
  const allow = [...((raw.allow as Entry[] | undefined) ?? []), ...added.map((a) => ({ package: a.id, reason: 'adopted', added: today }))];
  raw = { ...raw, allow };

  const final = parsePolicy(raw);
  if (!final.ok) return stop(`invalid policy:\n${final.errors.map((m) => `- ${m}`).join('\n')}`);

  const files = [...changedFiles];
  if (added.length || !hadPolicy) files.unshift({ path: policyRel, contents: `${JSON.stringify(raw, null, 2)}\n` });
  if (!files.length) {
    notice('nothing to adopt');
    setOutput('result', 'pass', env);
    return 0;
  }

  // 5. Branch, commit, PR.
  const body = prBody(added, cooldownDays, [...notGated].sort(), changedFiles.length);
  try {
    const gh = github(deps.fetch, inputs.githubToken, repo, { selfLogin: env.DECANT_GITHUB_LOGIN || undefined });
    // The files come from the checkout, so it must be the live default-branch head.
    const co = await defaultHeadCheckout(gh, env, 'adopt');
    if (!co.ok) return stop(co.message);
    const base = co.base;
    const open = await gh.findOpenPr(BRANCH);
    let head: string;
    if (open) head = open.headSha;
    else {
      head = co.sha;
      try {
        await gh.createBranch(BRANCH, head);
      } catch (e) {
        // A stale branch with no open PR (e.g. a merged or closed adopt): reset it to the default head.
        if (!/HTTP 422/.test((e as Error).message)) throw e;
        await gh.updateRef(BRANCH, head);
      }
    }
    if (open) {
      let same = true;
      for (const f of files) if ((await gh.fileAt(f.path, head)) !== f.contents) same = false;
      if (same) {
        notice('adopt PR already up to date');
        setOutput('pr-number', String(open.number), env);
        setOutput('result', 'pass', env);
        return 0;
      }
    }
    await gh.commitFiles(BRANCH, head, 'decant: adopt', files);
    if (open) {
      await gh.updatePr(open.number, { body });
      notice(`updated #${open.number}`);
      setOutput('pr-number', String(open.number), env);
    } else {
      const pr = await gh.openPr({ head: BRANCH, base, title: 'decant: adopt', body, labels: ['decant:adopt'] });
      notice(`opened ${pr.url}`);
      setOutput('pr-number', String(pr.number), env);
    }
  } catch (e) {
    return stop(`decant adopt: ${(e as Error).message}`);
  }
  setOutput('result', 'pass', env);
  return 0;
}

function prBody(added: { id: string; at: Date }[], cooldownDays: number, notGated: string[], normalized: number): string {
  const lines = [
    'One-time adoption of decant. Review, then merge.',
    '',
    `Versions already in your lockfiles that are still inside the ${cooldownDays}-day cooldown get an allow entry, so installs keep working on day one.`,
  ];
  if (added.length) {
    lines.push('', '| package | published | ages out |', '| --- | --- | --- |');
    for (const a of added) lines.push(`| ${safe(a.id)} | ${ymd(a.at)} | ${ymd(new Date(a.at.getTime() + cooldownDays * DAY))} |`);
  } else lines.push('', 'No versions are inside the cooldown; no allow entries needed.');
  if (normalized) lines.push('', `${normalized} lockfile(s) normalized to registry.npmjs.org URLs.`);
  if (notGated.length) {
    lines.push('', '**not gated by decant** (not from the public registry):', '', ...notGated.map((id) => `- ${safe(id)}`));
  }
  lines.push('', '**Next steps:** merge this PR; the sync on the default branch then applies the policy.');
  return lines.join('\n');
}
