import type { Ecosystem } from './ids';

export interface Parsed {
  major: number;
  minor: number;
  patch: number;
  /** Prerelease identifiers; empty for a release. Build metadata is dropped. */
  pre: string[];
}

const NUM = '(0|[1-9]\\d*)';
const PRE_ID = '(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)';
const RE = new RegExp(
  `^${NUM}\\.${NUM}\\.${NUM}(?:-(${PRE_ID}(?:\\.${PRE_ID})*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`,
);

export function parseVersion(v: string, eco: Ecosystem): Parsed | null {
  let s = v;
  if (eco === 'go') {
    if (!s.startsWith('v')) return null;
    s = s.slice(1);
  }
  const m = RE.exec(s);
  if (!m) return null;
  const [major, minor, patch] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return { major, minor, patch, pre: m[4] ? m[4].split('.') : [] };
}

const isNum = (s: string) => /^\d+$/.test(s);

function cmpId(a: string, b: string): number {
  const an = isNum(a);
  const bn = isNum(b);
  if (an && bn) {
    const x = BigInt(a);
    const y = BigInt(b);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  if (an) return -1; // numeric ranks below alphanumeric
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

function cmpParsed(a: Parsed, b: Parsed): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  if (a.pre.length === 0 || b.pre.length === 0) {
    return a.pre.length === b.pre.length ? 0 : a.pre.length === 0 ? 1 : -1;
  }
  const n = Math.min(a.pre.length, b.pre.length);
  for (let i = 0; i < n; i++) {
    const c = cmpId(a.pre[i], b.pre[i]);
    if (c !== 0) return c;
  }
  return a.pre.length === b.pre.length ? 0 : a.pre.length < b.pre.length ? -1 : 1;
}

/** Negative when a < b. Unparseable versions sort lowest. */
export function compareVersions(a: string, b: string, eco: Ecosystem): number {
  const pa = parseVersion(a, eco);
  const pb = parseVersion(b, eco);
  if (!pa || !pb) return pa ? 1 : pb ? -1 : 0;
  return cmpParsed(pa, pb);
}

/** Go pseudo-versions always carry a prerelease segment, so this covers them too. */
export function isPrerelease(v: string, eco: Ecosystem): boolean {
  const p = parseVersion(v, eco);
  return p !== null && p.pre.length > 0;
}
