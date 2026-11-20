import { fileURLToPath } from 'node:url';
import type { Exec } from './exec';

/** Pinned in action/guarddog-requirements.txt (hash-locked). */
export const GUARDDOG_VERSION = '3.2.0';

export type GuardDogResult = { result: 'clean' | 'flagged'; details: string[] };
export type GuardDog = { bin: string };

function tail(s: string): string {
  return s.trim().split('\n').slice(-5).join(' ').slice(0, 500);
}

/**
 * The action's root directory. GitHub sets GITHUB_ACTION_PATH only for composite actions, and decant is a
 * node action, so it is an override only. Otherwise the directory is found from this code's own location:
 * one level up from action/dist/index.js (the bundle) or action/src/guarddog.ts (unbundled) is action/.
 */
export function actionDir(override: string | undefined, moduleUrl: string = import.meta.url): string {
  return override || fileURLToPath(new URL('..', moduleUrl));
}

export function requirementsPath(actionPath: string): string {
  return `${actionPath.replace(/\/+$/, '')}/guarddog-requirements.txt`;
}

/**
 * The Python that builds GuardDog's venv: DECANT_PYTHON if set, else the one actions/setup-python
 * installed (it exports pythonLocation), else python3 on PATH.
 */
export function pythonInterpreter(env: Record<string, string | undefined>): string {
  if (env.DECANT_PYTHON) return env.DECANT_PYTHON;
  if (env.pythonLocation) return `${env.pythonLocation.replace(/\/+$/, '')}/bin/python`;
  return 'python3';
}

/**
 * The Python minor versions the requirements were compiled for, from their `# decant-python: 3.12 3.13`
 * header line. A file without one throws: an unverified pairing is never installed.
 */
export function supportedPythons(requirements: string): string[] {
  const m = /^# decant-python:([ \d.]+)$/m.exec(requirements);
  const versions = (m?.[1] ?? '').trim().split(/\s+/).filter((v) => /^3\.\d+$/.test(v));
  if (versions.length === 0) throw new Error('guarddog-requirements.txt has no "# decant-python:" header');
  return versions;
}

/**
 * Creates a venv at `dir` and installs the hash-locked GuardDog from `<actionPath>/guarddog-requirements.txt`.
 * Binary wheels only: no sdist build (and so no package build code) ever runs. The pinned wheels exist only
 * for the Python versions in the file's header, so any other interpreter fails before pip runs.
 */
export async function installGuardDog(
  exec: Exec,
  readFile: (p: string) => Promise<string>,
  dir: string,
  actionPath: string,
  env: Record<string, string | undefined>,
): Promise<GuardDog> {
  const req = requirementsPath(actionPath);
  const supported = supportedPythons(await readFile(req));
  const python = pythonInterpreter(env);
  const ver = await exec(python, ['-c', 'import sys; print("%d.%d" % sys.version_info[:2])']);
  if (ver.code !== 0) throw new Error(`${python} failed to run: ${tail(ver.stderr)}`);
  const found = ver.stdout.trim();
  if (!supported.includes(found)) {
    throw new Error(
      `GuardDog's pinned dependencies are built for Python ${supported.join(' or ')}, but ${python} is ${found || 'unknown'}; ` +
        `add actions/setup-python with python-version: '${supported[0]}' before the decant scan step (see docs/adopt.md)`,
    );
  }
  const venv = await exec(python, ['-m', 'venv', dir]);
  if (venv.code !== 0) throw new Error(`${python} -m venv failed: ${tail(venv.stderr)}`);
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
