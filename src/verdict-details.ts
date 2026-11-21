/**
 * Verdict details are written by any project's CI, so they are validated on write and kept per writer
 * project (verdict_details). Readers merge the writers' lists: round-robin by severity, so no writer can
 * pad the list and push another writer's findings out, and the most severe findings of every writer
 * stay visible under the cap.
 */

export const MAX_DETAILS_PER_WRITE = 100;
export const MAX_MERGED_DETAILS = 200;

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3, negligible: 3, unknown: 4 };
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;

const str = (v: unknown, max: number): string | null => (typeof v === 'string' && v.trim() !== '' && v.length <= max ? v : null);

type Entry = { ident: string; rank: number; value: unknown };

function grypeEntry(d: unknown): Entry | null {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  const o = d as Record<string, unknown>;
  const id = typeof o.id === 'string' && ID_RE.test(o.id) ? o.id : null;
  const sev = typeof o.severity === 'string' ? o.severity.toLowerCase() : '';
  const pkg = str(o.package, 100);
  const version = str(o.version, 100);
  if (id === null || !(sev in SEV_RANK) || pkg === null || version === null || !Array.isArray(o.fixed)) return null;
  const fixed = o.fixed.filter((f) => str(f, 100) !== null) as string[];
  if (fixed.length !== o.fixed.length || fixed.length > 10) return null;
  return { ident: `${id}\u0000${pkg}\u0000${version}`, rank: SEV_RANK[sev]!, value: { id, severity: sev, package: pkg, version, fixed } };
}

function guarddogEntry(d: unknown): Entry | null {
  if (typeof d === 'string') return str(d, 100) === null ? null : { ident: d, rank: 4, value: d };
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  const o = d as Record<string, unknown>;
  const rule = str(o.rule, 100);
  if (rule === null) return null;
  const v: Record<string, unknown> = { rule };
  if (o.count !== undefined) {
    if (typeof o.count !== 'number' || !Number.isInteger(o.count) || o.count < 0) return null;
    v.count = o.count;
  }
  if (o.message !== undefined) {
    if (str(o.message, 200) === null) return null;
    v.message = o.message;
  }
  if (o.locations !== undefined) {
    if (!Array.isArray(o.locations) || o.locations.length > 5 || !o.locations.every((l) => str(l, 200) !== null)) return null;
    v.locations = o.locations;
  }
  return { ident: rule, rank: 4, value: v };
}

const entryOf = (scanner: string) => (scanner === 'grype' ? grypeEntry : scanner === 'guarddog' ? guarddogEntry : null);

function entries(scanner: string, details: unknown): Entry[] | null {
  const f = entryOf(scanner);
  if (f === null || !Array.isArray(details)) return null;
  const seen = new Set<string>();
  const out: Entry[] = [];
  for (const d of details) {
    const e = f(d);
    if (e === null || seen.has(e.ident)) continue;
    seen.add(e.ident);
    out.push(e);
  }
  // Stable: most severe first, the writer's own order within a severity.
  return out.map((e, i) => ({ e, i })).sort((a, b) => a.e.rank - b.e.rank || a.i - b.i).map((x) => x.e);
}

/**
 * Validated details for storage: for scanners with a known shape (grype, guarddog), malformed entries are
 * dropped, duplicates removed, most severe kept first, at most MAX_DETAILS_PER_WRITE. Other scanners' details
 * (e.g. osv's {malicious: [...]}) are stored as given.
 */
export function sanitizeDetails(scanner: string, details: unknown): unknown {
  const es = entries(scanner, details);
  if (es === null) return details; // not a list (or an unknown scanner): stored on the verdict row as given, never per writer
  return es.slice(0, MAX_DETAILS_PER_WRITE).map((e) => e.value);
}

/**
 * Merges each writer's stored list (newest writer first): severity tier by tier, taking writers in turn,
 * deduplicated, at most MAX_MERGED_DETAILS. Scanners without a known shape: the newest writer's details.
 */
export function mergeDetails(scanner: string, perWriter: unknown[]): unknown {
  if (perWriter.length === 0) return undefined;
  if (entryOf(scanner) === null) return perWriter[0];
  const lists = perWriter.map((d) => entries(scanner, d) ?? []);
  const out: unknown[] = [];
  const seen = new Set<string>();
  for (let rank = 0; rank <= 4 && out.length < MAX_MERGED_DETAILS; rank++) {
    const tiers = lists.map((l) => l.filter((e) => e.rank === rank));
    for (let i = 0; out.length < MAX_MERGED_DETAILS && tiers.some((t) => i < t.length); i++) {
      for (const t of tiers) {
        const e = t[i];
        if (!e || seen.has(e.ident) || out.length >= MAX_MERGED_DETAILS) continue;
        seen.add(e.ident);
        out.push(e.value);
      }
    }
  }
  return out;
}

/** A verdict row's details for readers: the writers' lists merged, or (rows before 0008) the row's own. */
export function verdictDetails(scanner: string, rowDetails: string | null, writersJson: string | null): unknown {
  let writers: unknown[] = [];
  try {
    const w = writersJson === null ? [] : (JSON.parse(writersJson) as unknown);
    if (Array.isArray(w)) writers = w;
  } catch {
    // unreadable: fall back to the row
  }
  if (writers.length > 0) return mergeDetails(scanner, writers);
  if (rowDetails === null) return undefined;
  try {
    return JSON.parse(rowDetails) as unknown;
  } catch {
    return undefined;
  }
}
