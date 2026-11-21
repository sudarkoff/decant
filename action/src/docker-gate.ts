import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { formatPackageId } from '../../src/ids';
import { isKnownRegistry, ociClient } from '../../src/oci';
import type { DecantClient, ImageDecision } from './decant-client';
import type { ActionDeps } from './deps';
import { findDockerfiles, parseDockerfile, type FromLine } from './dockerfile';
import { fileAtCommit } from './git';
import { error, warning } from './gh-io';
import { GRYPE_VERSION, grypeArch, grypeEnv, grypeVerdict, installGrype, scanImage, type GrypeFinding } from './grype';

/** Registry- and image-derived text: the same allowlist the scan report uses for package names. */
export const safe = (s: string) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, '?');
/** A Dockerfile line shown in a code span: also spaces, '#', '=' and '$'; never a backtick, pipe or bracket. */
const safeLine = (s: string) => s.replace(/[^A-Za-z0-9@._~/+:= #=$-]/g, '?');
/** Messages (registry errors, Grype stderr) in log annotations: prose punctuation, no markup characters. */
const safeText = (s: string) => s.replace(/\s+/g, ' ').replace(/[^A-Za-z0-9._~/+:,;=!?#%&*()'"{}$^@ -]/g, '?');
const MAX_IMAGES = 200;
const MAX_LISTED = 5;
const fmtTime = (iso: string) => `${iso.slice(0, 16).replace('T', ' ')} UTC`;

export type ImageRow = {
  /** Dockerfile (relative) and line of the first use. */
  file: string;
  line: number;
  /** name@digest, the tag-less reference decant gates; or the text as written when it is not a pinned image. */
  image: string;
  cooldown: string;
  grype: string;
  problems: string[];
  notes: string[];
};

type Candidate = { name: string; digest: string; platform?: string; uses: { file: string; line: number }[] };

/** Short list of findings for a report cell: `CVE (pkg ver → fix)`. */
function findingList(fs: GrypeFinding[]): string {
  const shown = fs.slice(0, MAX_LISTED).map((f) => `${safe(f.id)} (${safe(f.package)} ${safe(f.version)}${f.fixed.length ? ` → ${safe(f.fixed[0]!)}` : ''})`);
  return `${shown.join(', ')}${fs.length > MAX_LISTED ? `, +${fs.length - MAX_LISTED} more` : ''}`;
}

/** The FROM a reviewer should write: the image as written, pinned to `digest`. */
function pinned(f: FromLine, digest: string): string {
  const base = f.text.replace(/@sha256:[0-9a-f]*$/, '');
  if (f.syntax) return `# syntax=${base}@${digest}`;
  if (f.via === 'copy') return `COPY --from=${base}@${digest}`;
  if (f.via === 'mount') return `RUN --mount=from=${base}@${digest}`;
  return `FROM ${f.platform ? `--platform=${f.platform} ` : ''}${base}@${digest}`;
}

export type GateOpts = {
  deps: ActionDeps;
  wd: string;
  baseSha: string;
  ref: string;
  client: DecantClient;
};

/** Dockerfiles that differ from base (relative to wd); symlinked ones count as changed. */
export async function changedDockerfiles(deps: ActionDeps, wd: string, baseSha: string): Promise<{ changed: string[]; unchanged: string[]; symlinks: string[] }> {
  const tree = await findDockerfiles(wd, deps.fs);
  const changed: string[] = [];
  const unchanged: string[] = [];
  for (const rel of tree.files) {
    if ((await fileAtCommit(deps, wd, baseSha, rel)) !== (await deps.fs.readFile(join(wd, rel)))) changed.push(rel);
    else unchanged.push(rel);
  }
  return { changed, unchanged, symlinks: tree.symlinks };
}

/**
 * The PR gate for base images. Every FROM (and `# syntax=` frontend) in a changed Dockerfile must be scratch,
 * an earlier stage, or pinned by digest. Digests not already used at base must pass decant's decision
 * (cooldown measured from when decant first verified the digest; allow and block entries) and Grype: High or
 * Critical findings with a fix fail, without one they are reported. Anything decant cannot read or check fails.
 */
export async function dockerGate(o: GateOpts): Promise<{ rows: ImageRow[]; fatal: string | null }> {
  const { deps, wd, baseSha, ref, client } = o;
  const env = deps.env;
  const rows: ImageRow[] = [];
  const files = await changedDockerfiles(deps, wd, baseSha);
  if (files.symlinks.length) return { rows, fatal: `symlinked Dockerfile or directory (${files.symlinks.map(safe).join(', ')}); decant does not scan through symlinks` };
  if (!files.changed.length) return { rows, fatal: null };

  // Digests already in use at base: in unchanged Dockerfiles, and in the base version of changed ones.
  const atBase = new Set<string>();
  const addBase = (text: string | null) => {
    if (text === null) return;
    for (const f of parseDockerfile(text).froms) if (f.kind === 'image' && f.ref?.digest) atBase.add(`${f.ref.name}@${f.ref.digest}`);
  };
  for (const rel of files.unchanged) addBase(await deps.fs.readFile(join(wd, rel)));
  for (const rel of files.changed) addBase(await fileAtCommit(deps, wd, baseSha, rel));

  const oci = ociClient({ fetch: deps.fetch });
  const candidates = new Map<string, Candidate>();
  for (const rel of files.changed) {
    const parsed = parseDockerfile(await deps.fs.readFile(join(wd, rel)));
    for (const e of parsed.errors) {
      rows.push({ file: rel, line: Number(/^line (\d+)/.exec(e)?.[1] ?? 0), image: '—', cooldown: '—', grype: '—', problems: ['cannot read this line (see log)'], notes: [] });
      error(safeText(e.replace(/^line (\d+): /, `${rel}:$1: `)), join(wd, rel));
    }
    for (const a of parsed.argLines ?? []) {
      warning(`${safe(rel)}:${a.line}: --mount value comes from ${a.args.map((x) => `ARG ${safe(x)}`).join(', ')}; a --build-arg at build time bypasses this check`, join(wd, rel));
    }
    for (const f of parsed.froms) {
      if (f.args?.length) {
        warning(
          `${safe(rel)}:${f.line}: value comes from ${f.args.map((a) => `ARG ${safe(a)}`).join(', ')}; a --build-arg at build time bypasses this check`,
          join(wd, rel),
        );
      }
      if (f.kind !== 'image' || !f.ref) continue;
      const r = f.ref;
      if (r.digest) {
        const k = `${r.name}@${r.digest}`;
        if (atBase.has(k)) continue;
        const c = candidates.get(k) ?? { name: r.name, digest: r.digest, platform: f.platform, uses: [] };
        c.uses.push({ file: rel, line: f.line });
        candidates.set(k, c);
        continue;
      }
      // Not pinned: say what to write, from the digest the tag resolves to now.
      const res = await oci.resolveTag(r.name, r.tag ?? 'latest');
      const fix =
        res.status === 'ok'
          ? `pin it: \`${safeLine(pinned(f, res.digest))}\``
          : res.status === 'unsupported'
            ? `can't resolve: registry ${safe(r.registry)} is not supported; pin the digest you build from`
            : res.status === 'denied'
              ? "can't resolve: anonymous pull refused (private image?); pin the digest you build from"
              : `can't resolve the tag (${res.status === 'not-found' ? 'not found' : safeText(res.message)})`;
      const what = f.syntax ? 'syntax frontend image is not pinned by digest' : f.via ? `${f.via === 'copy' ? 'COPY --from' : 'RUN --mount from'} image is not pinned by digest` : 'not pinned by digest';
      rows.push({ file: rel, line: f.line, image: safe(f.text), cooldown: '—', grype: '—', problems: [`${what}; ${fix}`], notes: [] });
      error(`${safe(rel)}:${f.line}: ${safe(f.text)} is ${what}; ${fix.replace(/`/g, '')}`, join(wd, rel));
    }
  }
  if (candidates.size > MAX_IMAGES) return { rows, fatal: `too many new image digests (${candidates.size}); split the change` };
  if (!candidates.size) return { rows, fatal: null };

  const list = [...candidates.values()];
  const reply = await client.images(ref, list.map((c) => ({ name: c.name, digest: c.digest })));
  const decisions = new Map(reply.images.map((d) => [`${d.name}@${d.digest}`, d]));

  let installed: Promise<string> | null = null;
  const grype = () =>
    (installed ??= installGrype(deps.fetch, deps.exec, deps.fs, `${env.RUNNER_TEMP || tmpdir()}/decant-grype`, grypeArch(env.DECANT_GRYPE_PLATFORM || process.platform, env.DECANT_GRYPE_ARCH || process.arch)).then((g) => g.bin));
  const grypeEnvs = grypeEnv(`${env.RUNNER_TEMP || tmpdir()}/decant-grype-db`);

  for (const c of list) {
    const id = formatPackageId({ eco: 'docker', name: c.name, version: c.digest });
    const use = c.uses[0]!;
    const row: ImageRow = { file: use.file, line: use.line, image: safe(`${c.name}@${c.digest}`), cooldown: '—', grype: '—', problems: [], notes: [] };
    rows.push(row);
    if (c.uses.length > 1) row.notes.push(`also ${c.uses.slice(1).map((u) => `${safe(u.file)}:${u.line}`).join(', ')}`);
    const d: ImageDecision | undefined = decisions.get(`${c.name}@${c.digest}`);
    if (!d) {
      row.problems.push('decant returned no decision');
      continue;
    }
    if (d.decision === 'blocked') {
      row.cooldown = 'blocked';
      row.problems.push(`blocked by decant (${d.blocks.map((b) => `${safe(b.source)}: ${b.reason.replace(/[|\n<>`]/g, ' ').slice(0, 100)}`).join('; ')})`);
      continue;
    }
    if (d.decision === 'allow') row.cooldown = d.allowed ? 'allowed by policy' : `cleared (first seen ${fmtTime(d.firstSeen!)})`;
    else if (d.clock === 'unverified') {
      row.cooldown = 'not verified';
      row.problems.push(`decant could not verify this digest in the registry (${safeText(d.note ?? 'unknown')}); it stays in cooldown until it can`);
    } else {
      row.cooldown = `until ${fmtTime(d.eligibleAt!)}`;
      row.problems.push(`waiting for cooldown until ${fmtTime(d.eligibleAt!)} (first seen by decant ${fmtTime(d.firstSeen!)}${d.clock === 'project' ? ', this project only' : ''})`);
    }

    const cached = await client.getVerdicts(id);
    if (cached.some((v) => v.result === 'malicious')) row.problems.push(`malicious (${cached.filter((v) => v.result === 'malicious').map((v) => safe(v.scanner)).join(', ')})`);

    const registry = c.name.slice(0, c.name.indexOf('/'));
    if (!isKnownRegistry(registry)) {
      row.grype = 'not scanned';
      if (d.allowed) row.notes.push(`registry ${safe(registry)} is not scannable; accepted by an allow entry`);
      else row.problems.push(`not scannable: decant scans Docker Hub and ghcr.io images only; add an allow entry for ${safe(id)} to accept it`);
      continue;
    }
    try {
      const res = await scanImage(deps.exec, await grype(), c.name, c.digest, grypeEnvs, c.platform);
      const v = grypeVerdict(res);
      await client.putVerdict({ package: id, scanner: 'grype', scannerVersion: GRYPE_VERSION, result: v.result, details: v.details });
      row.grype = res.failing.length ? `${res.failing.length} fixable High/Critical` : res.unfixed.length ? `${res.unfixed.length} High/Critical, no fix` : 'clean';
      if (res.failing.length) row.problems.push(`vulnerable: ${findingList(res.failing)}`);
      if (res.unfixed.length) {
        row.notes.push(`no fix yet: ${findingList(res.unfixed)}`);
        warning(`${row.image}: ${res.unfixed.length} High/Critical finding(s) with no fix yet`);
      }
    } catch (e) {
      row.grype = 'scan error';
      row.problems.push('scan error (see log)');
      error(`${row.image}: ${safeText((e as Error).message).slice(0, 300)}`);
    }
  }
  return { rows, fatal: null };
}

/** The image section of the scan report. */
export function renderImages(rows: ImageRow[], limit = Infinity): string[] {
  if (!rows.length) return [];
  const out = ['', '### Base images', '', '| Image | Dockerfile | Cooldown | Grype | Status |', '|---|---|---|---|---|'];
  let size = out.join('\n').length;
  for (const [i, r] of rows.entries()) {
    const status = r.problems.length ? `❌ ${r.problems.join('; ')}` : `✅ ${r.notes.length ? r.notes.join('; ') : 'ok'}`;
    const line = `| ${r.image === '—' ? '—' : `\`${r.image}\``} | ${safe(r.file)}:${r.line} | ${r.cooldown} | ${r.grype} | ${status.replace(/\|/g, '\\|')} |`;
    if (size + line.length + 1 > limit) {
      out.push(`\n… and ${rows.length - i} more image row(s) (see the job summary).`);
      break;
    }
    out.push(line);
    size += line.length + 1;
  }
  return out;
}

const OTHER_IMAGE_FILES = /^(?:(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml|fly\.toml)$/;

/** Files that may reference images outside Dockerfiles (compose, fly.toml): noted, never gated. */
export async function otherImageFiles(deps: ActionDeps, wd: string): Promise<string[]> {
  const out: string[] = [];
  const base = wd.replace(/\/+$/, '');
  const skip = new Set(['node_modules', '.git', 'vendor', 'testdata']);
  async function walk(rel: string): Promise<void> {
    for (const e of await deps.fs.readdir(rel ? `${base}/${rel}` : base)) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymlink) continue;
      if (e.isDir) {
        if (!skip.has(e.name)) await walk(r);
      } else if (OTHER_IMAGE_FILES.test(e.name)) out.push(r);
    }
  }
  await walk('');
  return out.sort();
}
