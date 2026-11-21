import { parsePackageId, PROJECT_ID_RE } from '../ids';

export type Severity = 'critical' | 'high' | 'moderate' | 'low';
export type ShipMode = 'auto' | 'approve';
export interface AllowEntry {
  package: string;
  reason: string;
  advisory?: string;
  added: string;
}
export interface BlockEntry {
  package: string;
  reason: string;
  advisory?: string;
}
export interface Policy {
  project: string;
  cooldownDays: number;
  autoShip: Record<Severity, ShipMode>;
  allow: AllowEntry[];
  block: BlockEntry[];
}

export const SEVERITIES: Severity[] = ['critical', 'high', 'moderate', 'low'];
export const DEFAULT_AUTOSHIP: Record<Severity, ShipMode> = {
  critical: 'auto',
  high: 'auto',
  moderate: 'approve',
  low: 'approve',
};
export const ADVISORY_RE = /^(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,}|[A-Z]+-\d{4}-[A-Za-z0-9-]+)$/;
const TOP_KEYS = new Set(['$schema', 'project', 'cooldownDays', 'autoShip', 'allow', 'block']);

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isRealDate(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

function entry(raw: unknown, path: string, withAdded: boolean, errors: string[]): { package: string; reason: string; advisory?: string; added?: string } | null {
  if (!isObj(raw)) {
    errors.push(`${path} must be an object`);
    return null;
  }
  const allowed = new Set(['package', 'reason', 'advisory', ...(withAdded ? ['added'] : [])]);
  for (const k of Object.keys(raw)) if (!allowed.has(k)) errors.push(`${path}.${k} is not allowed`);
  const n = errors.length;
  const out: { package: string; reason: string; advisory?: string; added?: string } = { package: '', reason: '' };
  if (typeof raw.package !== 'string' || parsePackageId(raw.package) === null) errors.push(`${path}.package must be a package ID like npm:name@1.0.0 (images: docker:docker.io/library/node@sha256:<64 hex>)`);
  else out.package = raw.package;
  if (typeof raw.reason !== 'string' || raw.reason === '') errors.push(`${path}.reason must be a non-empty string`);
  else out.reason = raw.reason;
  if (raw.advisory !== undefined) {
    if (typeof raw.advisory !== 'string' || !ADVISORY_RE.test(raw.advisory)) errors.push(`${path}.advisory is not a valid advisory ID`);
    else out.advisory = raw.advisory;
  }
  if (withAdded) {
    if (typeof raw.added !== 'string' || !isRealDate(raw.added)) errors.push(`${path}.added must be a real date in YYYY-MM-DD form`);
    else out.added = raw.added;
  }
  return errors.length === n ? out : null;
}

export function parsePolicy(input: unknown): { ok: true; policy: Policy } | { ok: false; errors: string[] } {
  if (!isObj(input)) return { ok: false, errors: ['policy must be a JSON object'] };
  const errors: string[] = [];
  for (const k of Object.keys(input)) if (!TOP_KEYS.has(k)) errors.push(`unknown key: ${k}`);

  let project = '';
  if (typeof input.project !== 'string' || input.project === '') errors.push('project must be a non-empty string');
  else if (!PROJECT_ID_RE.test(input.project)) errors.push(`project must match ${PROJECT_ID_RE.source}`);
  else project = input.project;

  let cooldownDays = 7;
  if (input.cooldownDays !== undefined) {
    const c = input.cooldownDays;
    if (typeof c !== 'number' || !Number.isInteger(c) || c < 0 || c > 365) errors.push('cooldownDays must be an integer from 0 to 365');
    else cooldownDays = c;
  }

  const autoShip = { ...DEFAULT_AUTOSHIP };
  if (input.autoShip !== undefined) {
    if (!isObj(input.autoShip)) errors.push('autoShip must be an object');
    else {
      for (const [k, v] of Object.entries(input.autoShip)) {
        if (!(SEVERITIES as string[]).includes(k)) errors.push(`autoShip.${k} is not a known severity`);
        else if (v !== 'auto' && v !== 'approve') errors.push(`autoShip.${k} must be 'auto' or 'approve'`);
        else autoShip[k as Severity] = v;
      }
    }
  }

  const allow: AllowEntry[] = [];
  const block: BlockEntry[] = [];
  for (const [key, withAdded] of [['allow', true], ['block', false]] as const) {
    const raw = input[key];
    if (raw === undefined) continue;
    if (!Array.isArray(raw)) {
      errors.push(`${key} must be an array`);
      continue;
    }
    raw.forEach((r, i) => {
      const e = entry(r, `${key}[${i}]`, withAdded, errors);
      if (e) (withAdded ? allow : block).push(e as AllowEntry & BlockEntry);
    });
  }

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, policy: { project, cooldownDays, autoShip, allow, block } };
}
