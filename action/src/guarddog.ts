import type { Exec } from './exec';

/** Pinned in action/guarddog-requirements.txt (hash-locked). */
export const GUARDDOG_VERSION = '3.2.0';

export type GuardDogResult = { result: 'clean' | 'flagged'; details: string[] };
export type GuardDog = { bin: string };

function tail(s: string): string {
  return s.trim().split('\n').slice(-5).join(' ').slice(0, 500);
}

/**
 * Creates a venv at `dir` and installs the hash-locked GuardDog from `<actionPath>/guarddog-requirements.txt`.
 * Binary wheels only: no sdist build (and so no package build code) ever runs.
 */
export async function installGuardDog(exec: Exec, dir: string, actionPath: string): Promise<GuardDog> {
  const venv = await exec('python3', ['-m', 'venv', dir]);
  if (venv.code !== 0) throw new Error(`python3 -m venv failed: ${tail(venv.stderr)}`);
  const req = `${actionPath.replace(/\/+$/, '')}/guarddog-requirements.txt`;
  const pip = await exec(`${dir}/bin/pip`, [
    'install',
    '--disable-pip-version-check',
    '--require-hashes',
    '--no-deps',
    '--only-binary',
    ':all:',
    '-r',
    req,
  ]);
  if (pip.code !== 0) throw new Error(`pip install of GuardDog failed: ${tail(pip.stderr)}`);
  return { bin: `${dir}/bin/guarddog` };
}

const hasFindings = (v: unknown): boolean =>
  Array.isArray(v) ? v.length > 0 : typeof v === 'object' && v !== null ? Object.keys(v).length > 0 : typeof v === 'string' ? v !== '' : !!v;

/**
 * GuardDog 3.x `--output-format json` → clean | flagged. `capability-*` rules describe what code can
 * do (network, spawn, fs) and fire on most real packages, so they are informational; any other rule
 * with findings, or any correlated risk, means flagged. A report with `errors` or without `results`
 * throws: an incomplete scan is never clean.
 */
export function parseGuardDogJson(stdout: string): GuardDogResult {
  let doc: { results?: unknown; errors?: unknown; risks?: unknown; risk_score?: { label?: unknown } };
  try {
    doc = JSON.parse(stdout) as typeof doc;
  } catch {
    throw new Error('guarddog: invalid JSON output');
  }
  if (doc.errors && typeof doc.errors === 'object' && Object.keys(doc.errors).length > 0) {
    throw new Error(`guarddog reported errors: ${Object.keys(doc.errors).join(', ')}`);
  }
  if (!doc.results || typeof doc.results !== 'object') throw new Error('guarddog: no results in output');
  const details: string[] = [];
  for (const [rule, v] of Object.entries(doc.results as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (rule.startsWith('capability-') || !hasFindings(v)) continue;
    details.push(Array.isArray(v) ? `${rule} (${v.length})` : rule);
  }
  if (Array.isArray(doc.risks) && doc.risks.length > 0) {
    const label = typeof doc.risk_score?.label === 'string' ? doc.risk_score.label : 'unlabelled';
    details.push(`risk: ${label}`);
  }
  return { result: details.length > 0 ? 'flagged' : 'clean', details };
}

async function scan(exec: Exec, bin: string, eco: 'npm' | 'go', path: string): Promise<GuardDogResult> {
  // `path` must be an existing absolute file: guarddog treats anything else as a remote name and downloads it.
  const r = await exec(bin, [eco, 'scan', path, '--output-format', 'json', '--sandbox']);
  if (r.code !== 0) throw new Error(`guarddog ${eco} scan exited ${r.code}: ${tail(r.stderr)}`);
  return parseGuardDogJson(r.stdout);
}

/** Scans a local npm tarball (.tgz). */
export const scanNpm = (exec: Exec, bin: string, tgzPath: string) => scan(exec, bin, 'npm', tgzPath);

/** Scans a local Go module zip. GuardDog 3.2.0 supports Go, so this never returns null. */
export const scanGo = (exec: Exec, bin: string, zipPath: string) => scan(exec, bin, 'go', zipPath);
