import type { Severity } from './policy/schema';

const GHSA_SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'moderate', MEDIUM: 'moderate', LOW: 'low' };
const RANK: Record<Severity | 'unknown', number> = { unknown: 0, low: 1, moderate: 2, high: 3, critical: 4 };

export function maxSeverity(...s: (Severity | 'unknown')[]): Severity | 'unknown' {
  return s.reduce<Severity | 'unknown'>((a, b) => (RANK[b] > RANK[a] ? b : a), 'unknown');
}

const CVSS_W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

/** CVSS v3.x "Roundup": smallest one-decimal number >= x, robust to float error (spec appendix A). */
function roundup(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** CVSS v3.0/v3.1 base score from a vector string; null for anything else (v2, v4, malformed). */
export function cvss31BaseScore(vector: string): number | null {
  const parts = vector.split('/');
  if (parts[0] !== 'CVSS:3.1' && parts[0] !== 'CVSS:3.0') return null;
  const m: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const [k, v] = p.split(':');
    if (k && v) m[k] = v;
  }
  const S = m.S;
  if (S !== 'U' && S !== 'C') return null;
  const av = CVSS_W.AV[m.AV as keyof typeof CVSS_W.AV];
  const ac = CVSS_W.AC[m.AC as keyof typeof CVSS_W.AC];
  const ui = CVSS_W.UI[m.UI as keyof typeof CVSS_W.UI];
  const pr = { N: 0.85, L: S === 'C' ? 0.68 : 0.62, H: S === 'C' ? 0.5 : 0.27 }[m.PR as 'N' | 'L' | 'H'];
  const [c, i, a] = [m.C, m.I, m.A].map((x) => CVSS_W.CIA[x as keyof typeof CVSS_W.CIA]);
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const expl = 8.22 * av * ac * pr! * ui;
  if (impact <= 0) return 0;
  return roundup(Math.min((S === 'U' ? 1 : 1.08) * (impact + expl), 10));
}

function scoreSeverity(score: number): Severity | 'unknown' {
  return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'moderate' : score > 0 ? 'low' : 'unknown';
}

/** Max of the GHSA database_specific.severity and any CVSS v3 base score (GHSA wins over a lower CVSS), else 'unknown'. */
export function severityOf(r: {
  database_specific?: { severity?: unknown };
  severity?: { type?: string; score?: string }[];
}): Severity | 'unknown' {
  const sev = r.database_specific?.severity;
  const db = typeof sev === 'string' ? (GHSA_SEVERITY[sev.toUpperCase()] ?? 'unknown') : 'unknown';
  const cvss = (r.severity ?? [])
    .filter((x) => x.type === 'CVSS_V3' && typeof x.score === 'string')
    .map((x) => cvss31BaseScore(x.score!))
    .map((n) => (n === null ? 'unknown' : scoreSeverity(n)));
  return maxSeverity(db, ...cvss);
}

