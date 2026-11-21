import { join } from 'node:path';
import { formatPackageId } from '../../src/ids';
import { isKnownRegistry, ociClient } from '../../src/oci';
import type { Severity } from '../../src/policy/schema';
import type { DecantClient } from './decant-client';
import type { ActionDeps } from './deps';
import { findDockerfiles, parseDockerfile } from './dockerfile';
import { warning } from './gh-io';
import { GRYPE_VERSION, grypeArch, grypeEnv, grypeVerdict, installGrype, isSerious, scanImage, type GrypeFinding } from './grype';

/** The ref the audit's candidate digests are reported under: only main's allows apply (none are written for it). */
export const IMAGES_REF = 'audit-images';
const safe = (s: string) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, '?');
const short = (d: string) => d.slice(0, 'sha256:'.length + 12);

export type ImageBump = {
  name: string;
  tag: string;
  from: string;
  to: string;
  /** High/Critical findings of `from` that `to` no longer has. */
  fixes: GrypeFinding[];
  /** Findings `to` has that `from` did not (never High/Critical: such a bump is refused). */
  introduced: GrypeFinding[];
  severity: Severity;
  /** Repo-relative Dockerfiles changed. */
  files: string[];
};

export type ImageAudit = {
  bumps: ImageBump[];
  /** Changed Dockerfiles, repo-relative, with their new contents. */
  files: { path: string; contents: string }[];
  /** Summary lines (markdown, escaped). */
  lines: string[];
};

type Use = { rel: string; line: number };
type Group = { name: string; tag: string; digest: string; platform?: string; uses: Use[] };

const SEV_ORDER: Severity[] = ['critical', 'high', 'moderate', 'low'];

/**
 * The daily image audit. Re-scans every pinned base image in use (Docker Hub and ghcr.io) with Grype and
 * stores the verdicts, so new advisories reach the dashboard. For each `tag@digest`, resolves what the tag
 * points at now; decant records that digest (verifying it and starting its cooldown clock) and it becomes a
 * bump candidate once it has cleared the cooldown. A candidate ships only if it removes at least one High or
 * Critical finding of the pinned digest. Bumps go in the run's single security PR.
 */
export async function auditImages(deps: ActionDeps, client: DecantClient, wd: string, repoPath: (abs: string) => string): Promise<ImageAudit> {
  const env = deps.env;
  const lines: string[] = [];
  const tree = await findDockerfiles(wd, deps.fs);
  for (const l of tree.symlinks) warning(`${safe(l)}: symlinked Dockerfile or directory; not audited`);
  const groups = new Map<string, Group>();
  const texts = new Map<string, string>();
  const unpinned: string[] = [];
  for (const rel of tree.files) {
    const text = await deps.fs.readFile(join(wd, rel));
    texts.set(rel, text);
    const p = parseDockerfile(text);
    if (p.errors.length) lines.push(`- ${safe(rel)}: ${p.errors.length} line(s) decant cannot read (the PR scan fails on them)`);
    for (const f of p.froms) {
      if (f.kind !== 'image' || !f.ref) continue;
      if (!f.ref.digest) {
        unpinned.push(`${safe(rel)}:${f.line}`);
        continue;
      }
      const k = `${f.ref.name}|${f.ref.tag ?? ''}|${f.ref.digest}`;
      const g = groups.get(k) ?? { name: f.ref.name, tag: f.ref.tag ?? '', digest: f.ref.digest, platform: f.platform, uses: [] };
      g.uses.push({ rel, line: f.line });
      groups.set(k, g);
    }
  }
  if (unpinned.length) lines.push(`- Not pinned by digest: ${unpinned.slice(0, 10).join(', ')}${unpinned.length > 10 ? ', …' : ''}`);
  if (!groups.size) return { bumps: [], files: [], lines };

  let bin: Promise<string> | null = null;
  const grype = () =>
    (bin ??= installGrype(deps.fetch, deps.exec, deps.fs, `${env.RUNNER_TEMP}/decant-grype`, grypeArch(env.DECANT_GRYPE_PLATFORM || process.platform, env.DECANT_GRYPE_ARCH || process.arch)).then((g) => g.bin));
  const genv = grypeEnv(`${env.RUNNER_TEMP}/decant-grype-db`);
  const scans = new Map<string, Promise<GrypeFinding[] | null>>();
  /** All findings of name@digest (scanned once per run; verdict stored), or null on a scan error. */
  const findings = (name: string, digest: string, platform?: string) => {
    const k = `${name}@${digest}`;
    let s = scans.get(k);
    if (!s) {
      s = (async () => {
        try {
          const r = await scanImage(deps.exec, await grype(), name, digest, genv, platform);
          const v = grypeVerdict(r);
          await client.putVerdict({ package: formatPackageId({ eco: 'docker', name, version: digest }), scanner: 'grype', scannerVersion: GRYPE_VERSION, result: v.result, details: v.details });
          return r.findings;
        } catch (e) {
          warning(`${safe(k)}: ${safe((e as Error).message).slice(0, 200)}`);
          return null;
        }
      })();
      scans.set(k, s);
    }
    return s;
  };

  const oci = ociClient({ fetch: deps.fetch });
  const candidates: { g: Group; to: string }[] = [];
  for (const g of groups.values()) {
    const label = `\`${safe(g.name)}${g.tag ? `:${safe(g.tag)}` : ''}@${short(g.digest)}\``;
    if (!isKnownRegistry(g.name.slice(0, g.name.indexOf('/')))) {
      lines.push(`- ${label}: registry not supported; not scanned`);
      continue;
    }
    const all = await findings(g.name, g.digest, g.platform);
    const now = all === null ? null : all.filter(isSerious);
    const state = now === null ? 'scan error' : now.length ? `${now.length} High/Critical` : 'clean';
    if (!g.tag) {
      lines.push(`- ${label}: ${state}; no tag to follow`);
      continue;
    }
    const r = await oci.resolveTag(g.name, g.tag);
    if (r.status !== 'ok') {
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

  // mainOnly: only main's allow entries count, so no overlay (whatever its name) can skip a candidate's cooldown.
  const reply = await client.images(IMAGES_REF, [...new Map(candidates.map((c) => [`${c.g.name}@${c.to}`, { name: c.g.name, digest: c.to }])).values()], { mainOnly: true });
  const decision = new Map(reply.images.map((d) => [`${d.name}@${d.digest}`, d]));
  const bumps: ImageBump[] = [];
  const edited = new Map<string, string>();
  for (const { g, to } of candidates) {
    const label = `\`${safe(g.name)}:${safe(g.tag)}\` ${short(g.digest)} → ${short(to)}`;
    const d = decision.get(`${g.name}@${to}`);
    if (!d || d.decision !== 'allow') {
      const why = !d ? 'no decision' : d.decision === 'blocked' ? 'blocked' : d.eligibleAt ? `cooldown until ${d.eligibleAt.slice(0, 10)}` : 'not verified yet';
      lines.push(`- ${label}: newer digest waiting (${why})`);
      continue;
    }
    const before = await findings(g.name, g.digest, g.platform);
    const after = await findings(g.name, to, g.platform);
    if (before === null || after === null) {
      lines.push(`- ${label}: scan error; not bumped`);
      continue;
    }
    const beforeIds = new Set(before.map((f) => f.id));
    const afterIds = new Set(after.map((f) => f.id));
    const fixes = [...new Map(before.filter((f) => isSerious(f) && !afterIds.has(f.id)).map((f) => [f.id, f])).values()];
    const introduced = [...new Map(after.filter((f) => !beforeIds.has(f.id)).map((f) => [f.id, f])).values()];
    if (!fixes.length) {
      lines.push(`- ${label}: fixes no High/Critical finding; not bumped`);
      continue;
    }
    const worse = introduced.filter(isSerious);
    if (worse.length) {
      lines.push(`- ${label}: would introduce ${worse.map((f) => `${safe(f.id)} (${f.severity})`).join(', ')}; not bumped`);
      continue;
    }
    // Rewrite the digest on each FROM (or its continuation lines); a digest set elsewhere (an ARG) is not touched.
    const pending = new Map<string, string>();
    let ok = true;
    for (const u of g.uses) {
      const text = pending.get(u.rel) ?? edited.get(u.rel) ?? texts.get(u.rel)!;
      const ls = text.split('\n');
      const at = ls.findIndex((l, i) => i >= u.line - 1 && i < u.line + 9 && l.includes(`@${g.digest}`));
      if (at < 0) {
        ok = false;
        break;
      }
      ls[at] = ls[at]!.replace(`@${g.digest}`, `@${to}`);
      pending.set(u.rel, ls.join('\n'));
    }
    if (!ok) {
      lines.push(`- ${label}: the digest is not written on its FROM line (an ARG?); not bumped`);
      continue;
    }
    for (const [rel, t] of pending) edited.set(rel, t);
    const severity = SEV_ORDER.find((s) => fixes.some((f) => f.severity === s)) ?? 'high';
    bumps.push({ name: g.name, tag: g.tag, from: g.digest, to, fixes, introduced, severity, files: [...new Set(g.uses.map((u) => repoPath(join(wd, u.rel))))] });
    lines.push(`- ${label}: bump fixes ${fixes.map((f) => safe(f.id)).join(', ')}`);
  }
  const files = [...edited].map(([rel, contents]) => ({ path: repoPath(join(wd, rel)), contents }));
  return { bumps, files, lines };
}
