import { createHash } from 'node:crypto';
import type { Severity } from '../../src/policy/schema';
import type { Fs } from './deps';
import type { Exec } from './exec';
import { request } from './http';

/**
 * Grype, pinned like GuardDog: one release, its linux tarballs' SHA-256 copied from that release's
 * grype_<v>_checksums.txt (and checked against the downloaded files). v0.121.3: the latest release at least
 * 7 days old on 2026-11-20. The vulnerability database is not pinned: Grype fetches it, and any failure
 * to check for or load it is a scan error (see grypeEnv).
 */
export const GRYPE_VERSION = '0.121.3';
export const GRYPE_SHA256: Record<'amd64' | 'arm64', string> = {
  amd64: 'e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85',
  arm64: 'b7815598d48da78bfd16f5b98ef28e1bb09c03d34fc8c3e350f99b6ccb3c7cba',
};
const DOWNLOAD_TIMEOUT_MS = 120_000;

export const grypeUrl = (arch: 'amd64' | 'arm64') =>
  `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${arch}.tar.gz`;

/** The release arch for this runner; Grype is installed only on Linux x64 and arm64 runners. */
export function grypeArch(platform: string = process.platform, arch: string = process.arch): 'amd64' | 'arm64' {
  if (platform !== 'linux') throw new Error(`Grype runs on Linux runners only (this is ${platform})`);
  if (arch === 'x64') return 'amd64';
  if (arch === 'arm64') return 'arm64';
  throw new Error(`no pinned Grype build for ${arch}`);
}

function tail(s: string): string {
  return s.trim().split('\n').slice(-5).join(' ').slice(0, 500);
}

/**
 * Downloads the pinned tarball, checks its SHA-256 before anything reads it, and extracts only the
 * `grype` binary into `dir`. A checksum mismatch throws and nothing is extracted.
 */
export async function installGrype(
  f: typeof fetch,
  exec: Exec,
  fs: Pick<Fs, 'mkdir' | 'writeBytes'>,
  dir: string,
  arch: 'amd64' | 'arm64',
  expected: Record<'amd64' | 'arm64', string> = GRYPE_SHA256,
): Promise<{ bin: string }> {
  const url = grypeUrl(arch);
  const res = await request(f, url, { redirect: 'follow' }, { label: `download Grype ${GRYPE_VERSION}`, timeoutMs: DOWNLOAD_TIMEOUT_MS });
  if (!res.ok) throw new Error(`download Grype ${GRYPE_VERSION}: HTTP ${res.status}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const got = createHash('sha256').update(bytes).digest('hex');
  if (got !== expected[arch]) throw new Error(`Grype ${GRYPE_VERSION} linux_${arch} checksum mismatch: got ${got}, pinned ${expected[arch]}`);
  await fs.mkdir(dir);
  const tarball = `${dir}/grype.tar.gz`;
  await fs.writeBytes(tarball, bytes);
  const x = await exec('tar', ['-xzf', tarball, '-C', dir, 'grype']);
  if (x.code !== 0) throw new Error(`extracting Grype failed: ${tail(x.stderr)}`);
  return { bin: `${dir}/grype` };
}

/**
 * Grype's environment: its database cached under the runner's temp dir, and every database problem fatal.
 * auto-update fetches the current DB; require-update-check fails the run if that check fails (rather than
 * scanning with a stale DB); validate-age refuses a DB older than Grype's limit.
 */
export function grypeEnv(cacheDir: string): Record<string, string> {
  return {
    GRYPE_DB_CACHE_DIR: cacheDir,
    GRYPE_DB_AUTO_UPDATE: 'true',
    GRYPE_DB_REQUIRE_UPDATE_CHECK: 'true',
    GRYPE_DB_VALIDATE_AGE: 'true',
    GRYPE_CHECK_FOR_APP_UPDATE: 'false',
  };
}

/** One finding. Package names, versions and ids come from the image (or the shared cache): untrusted text. */
export type GrypeFinding = { id: string; severity: Severity | 'unknown'; package: string; version: string; fixed: string[] };
export type GrypeResult = {
  findings: GrypeFinding[];
  /** High/Critical with a fixed version: these fail the PR. */
  failing: GrypeFinding[];
  /** High/Critical with no fix: reported, never failing. */
  unfixed: GrypeFinding[];
};

const SEV: Record<string, Severity> = { critical: 'critical', high: 'high', medium: 'moderate', low: 'low', negligible: 'low' };
const RANK: Record<Severity | 'unknown', number> = { critical: 0, high: 1, moderate: 2, unknown: 3, low: 4 };
const MAX_TEXT = 100;
const clip = (s: string) => {
  const t = s.replace(/\s+/g, ' ').trim();
  return t.length > MAX_TEXT ? `${t.slice(0, MAX_TEXT - 1)}…` : t;
};

export const isSerious = (f: GrypeFinding) => f.severity === 'critical' || f.severity === 'high';

/**
 * `grype -o json` → findings. A report that is not JSON or has no `matches` array throws: an incomplete
 * scan is never clean. Severity is matched case-insensitively (Medium → moderate, Negligible → low).
 */
export function parseGrypeJson(stdout: string): GrypeResult {
  let doc: { matches?: unknown };
  try {
    doc = JSON.parse(stdout) as typeof doc;
  } catch {
    throw new Error('grype: invalid JSON output');
  }
  if (!doc || !Array.isArray(doc.matches)) throw new Error('grype: no matches in output');
  const seen = new Map<string, GrypeFinding>();
  for (const m of doc.matches as unknown[]) {
    const v = (m as { vulnerability?: Record<string, unknown> })?.vulnerability;
    const a = (m as { artifact?: Record<string, unknown> })?.artifact;
    if (!v || typeof v.id !== 'string' || v.id.trim() === '') throw new Error('grype: a match has no vulnerability id');
    const sev = typeof v.severity === 'string' ? (SEV[v.severity.toLowerCase()] ?? 'unknown') : 'unknown';
    const fix = v.fix as { state?: unknown; versions?: unknown } | undefined;
    const fixed =
      fix?.state === 'fixed' && Array.isArray(fix.versions) ? fix.versions.filter((x): x is string => typeof x === 'string' && x.trim() !== '').map(clip) : [];
    const f: GrypeFinding = {
      id: clip(v.id),
      severity: sev,
      package: typeof a?.name === 'string' ? clip(a.name) : '?',
      version: typeof a?.version === 'string' ? clip(a.version) : '?',
      fixed,
    };
    seen.set(`${f.id}\u0000${f.package}\u0000${f.version}`, f);
  }
  const findings = [...seen.values()].sort((x, y) => RANK[x.severity] - RANK[y.severity] || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  return { findings, failing: findings.filter((f) => isSerious(f) && f.fixed.length > 0), unfixed: findings.filter((f) => isSerious(f) && f.fixed.length === 0) };
}

const PLATFORM_RE = /^linux\/[a-z0-9]+(?:\/v[0-9]+)?$/;

/**
 * Scans `name@digest` straight from the registry (`registry:` source: no Docker daemon). A literal
 * linux --platform from the FROM line is passed through; anything else (e.g. $BUILDPLATFORM) uses Grype's
 * default. A non-zero exit is a scan error.
 */
export async function scanImage(exec: Exec, bin: string, name: string, digest: string, env: Record<string, string>, platform?: string): Promise<GrypeResult> {
  const args = [`registry:${name}@${digest}`, '-o', 'json', '-q'];
  if (platform && PLATFORM_RE.test(platform)) args.push('--platform', platform);
  const r = await exec(bin, args, { env });
  if (r.code !== 0) throw new Error(`grype exited ${r.code}: ${tail(r.stderr)}`);
  return parseGrypeJson(r.stdout);
}

const MAX_DETAILS = 100;

/** The verdict decant stores: flagged when any High/Critical finding exists; details are those findings. */
export function grypeVerdict(r: GrypeResult): { result: 'clean' | 'flagged'; details: GrypeFinding[] } {
  const serious = r.findings.filter(isSerious).slice(0, MAX_DETAILS);
  return { result: serious.length ? 'flagged' : 'clean', details: serious };
}

/**
 * Verdict details read back from decant's shared cache (any project's CI wrote them): only well-formed
 * findings, clipped. Severity case-insensitive.
 */
export function normalizeGrypeDetails(details: unknown): GrypeFinding[] {
  if (!Array.isArray(details)) return [];
  const out: GrypeFinding[] = [];
  for (const d of details) {
    if (!d || typeof d !== 'object') continue;
    const o = d as Record<string, unknown>;
    if (typeof o.id !== 'string' || !o.id.trim()) continue;
    const s = typeof o.severity === 'string' ? o.severity.toLowerCase() : '';
    const severity: GrypeFinding['severity'] = s in RANK ? (s as Severity) : (SEV[s] ?? 'unknown');
    const fixed = Array.isArray(o.fixed) ? o.fixed.filter((x): x is string => typeof x === 'string' && x.trim() !== '').map(clip) : [];
    out.push({ id: clip(o.id), severity, package: typeof o.package === 'string' ? clip(o.package) : '?', version: typeof o.version === 'string' ? clip(o.version) : '?', fixed });
  }
  return out;
}
