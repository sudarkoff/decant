import { fileURLToPath } from 'node:url';
import type { Exec } from './exec';

/** Pinned in action/guarddog-requirements.txt (hash-locked). */
export const GUARDDOG_VERSION = '3.2.0';

/**
 * One rule that fired. Everything but `rule` comes from the scanned package (file paths, messages) or
 * from the shared verdict cache, so it is untrusted text: callers escape it before display.
 */
export type GuardDogFinding = { rule: string; count?: number; message?: string; locations?: string[] };
export type GuardDogResult = { result: 'clean' | 'flagged'; details: GuardDogFinding[] };

const MAX_LOCATIONS = 5;
const MAX_MESSAGE = 200;
const MAX_RULE = 100;
const MAX_LOCATION = 200;

/** Whitespace collapsed, cut to `n` chars (with … when cut). */
function clip(s: string, n: number): string {
  const t = s.replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

function finding(rule: string, count: number | undefined, message: unknown, locations: unknown[]): GuardDogFinding {
  const f: GuardDogFinding = { rule: clip(rule, MAX_RULE) };
  if (count !== undefined) f.count = count;
  if (typeof message === 'string' && message.trim()) f.message = clip(message, MAX_MESSAGE);
  const locs = [...new Set(locations.filter((l): l is string => typeof l === 'string' && l.trim() !== '').map((l) => clip(l, MAX_LOCATION)))];
  if (locs.length) f.locations = locs.slice(0, MAX_LOCATIONS);
  return f;
}

/**
 * Verdict `details` read back from decant's shared cache: the current finding objects, or the legacy
 * list of rule strings. Anything else is dropped, and the caps are re-applied (another project wrote it).
 */
export function normalizeFindings(details: unknown): GuardDogFinding[] {
  if (!Array.isArray(details)) return [];
  const out: GuardDogFinding[] = [];
  for (const d of details) {
    if (typeof d === 'string' && d.trim()) out.push({ rule: clip(d, MAX_RULE) });
    else if (d && typeof d === 'object' && typeof (d as { rule?: unknown }).rule === 'string') {
      const o = d as { rule: string; count?: unknown; message?: unknown; locations?: unknown };
      const count = typeof o.count === 'number' && Number.isInteger(o.count) && o.count >= 0 ? o.count : undefined;
      out.push(finding(o.rule, count, o.message, Array.isArray(o.locations) ? o.locations : []));
    }
  }
  return out;
}
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
  // Source-code rules give a list of {location, code, match, message}; metadata rules give a message string.
  const details: GuardDogFinding[] = [];
  for (const [rule, v] of Object.entries(doc.results as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (rule.startsWith('capability-') || !hasFindings(v)) continue;
    if (Array.isArray(v)) {
      const hits = v.map((h) => (h && typeof h === 'object' ? (h as { location?: unknown; message?: unknown }) : {}));
      details.push(finding(rule, v.length, hits.map((h) => h.message).find((m) => typeof m === 'string' && m.trim()), hits.map((h) => h.location)));
    } else {
      details.push(finding(rule, undefined, v, []));
    }
  }
  if (Array.isArray(doc.risks) && doc.risks.length > 0) {
    const label = typeof doc.risk_score?.label === 'string' ? doc.risk_score.label : 'unlabelled';
    const locs = doc.risks.map((r) => (r && typeof r === 'object' ? (r as { threat_location?: unknown }).threat_location : undefined));
    details.push(finding('risk', doc.risks.length, label, locs));
  }
  return { result: details.length > 0 ? 'flagged' : 'clean', details };
}

export const ARCHIVE_ANOMALY = 'archive-anomaly';

/**
 * The reasons guarddog 3.2.0's utils/archives.py gives for refusing a zip it cannot enumerate
 * unambiguously (the only two `archive parser anomaly` raises in that version). Each maps a match to
 * the canonical text recorded in the finding: only integers are taken from GuardDog's output.
 */
const ANOMALY_REASONS: { re: RegExp; text: (m: RegExpExecArray) => string }[] = [
  {
    re: /^multiple End-Of-Central-Directory records \(possible scan evasion via duplicate EOCD\)$/,
    text: () => 'multiple End-Of-Central-Directory records (possible scan evasion via duplicate EOCD)',
  },
  {
    re: /^(\d{1,9}) ZIP local file headers but zipfile enumerates (\d{1,9}) members from the central directory \(possible scan evasion via EOCD size\/offset differential\)$/,
    text: (m) =>
      `${Number(m[1])} ZIP local file headers but zipfile enumerates ${Number(m[2])} members from the central directory (possible scan evasion via EOCD size/offset differential)`,
  },
];

/**
 * GuardDog refuses an archive it cannot enumerate unambiguously (e.g. two End-Of-Central-Directory
 * records): cli.py logs `ERROR: Error occurred while scanning target <path>: '<reason>'` and exits 1.
 * Archives that contain zip test fixtures (Go modules like klauspost/compress) trip it. That is a reason
 * for a human to look, not an unscannable package, so it becomes a flag. GuardDog's output can carry
 * package-controlled text (file names in other errors), so the match is exact: exit 1, nothing on
 * stdout, stderr is that one line and nothing else, the target is the path decant passed, and the
 * reason is one of ANOMALY_REASONS. Anything else is a scan error.
 */
export function archiveAnomaly(r: { code: number; stdout: string; stderr: string }, path: string): string | null {
  if (r.code !== 1 || r.stdout.trim() !== '') return null;
  const lines = r.stderr.split('\n').filter((l) => l.trim() !== '');
  if (lines.length !== 1) return null;
  const prefix = `ERROR: Error occurred while scanning target ${path}: 'archive parser anomaly: `;
  const line = lines[0]!.replace(/\r$/, '');
  if (!line.startsWith(prefix) || !line.endsWith("'")) return null;
  const reason = line.slice(prefix.length, -1);
  for (const { re, text } of ANOMALY_REASONS) {
    const m = re.exec(reason);
    if (m) return `archive parser anomaly: ${text(m)}`;
  }
  return null;
}

async function scan(exec: Exec, bin: string, eco: 'npm' | 'go', path: string): Promise<GuardDogResult> {
  // `path` must be an existing absolute file: guarddog treats anything else as a remote name and downloads it.
  const r = await exec(bin, [eco, 'scan', path, '--output-format', 'json', '--sandbox']);
  if (r.code !== 0) {
    const anomaly = archiveAnomaly(r, path);
    if (anomaly) return { result: 'flagged', details: [{ rule: ARCHIVE_ANOMALY, message: anomaly }] };
    throw new Error(`guarddog ${eco} scan exited ${r.code}: ${tail(r.stderr)}`);
  }
  return parseGuardDogJson(r.stdout);
}

/** Scans a local npm tarball (.tgz). */
export const scanNpm = (exec: Exec, bin: string, tgzPath: string) => scan(exec, bin, 'npm', tgzPath);

/** Scans a local Go module zip. GuardDog 3.2.0 supports Go, so this never returns null. */
export const scanGo = (exec: Exec, bin: string, zipPath: string) => scan(exec, bin, 'go', zipPath);
