import { TtlCache } from '../cache';
import type { Ecosystem } from '../types';

/*
 * Per-isolate caches of decision inputs (see decider.ts for how they are read).
 *
 * - cooldowns: per project+ref, POLICY_TTL_MS.
 * - allows:    per project+ref+package, POLICY_TTL_MS.
 * - denied:    per package (global blocks ∪ publish-time conflicts), POLICY_TTL_MS.
 * - facts:     per version (publish time, stored_at: write-once), FACTS_TTL_MS.
 * - pins:      per package, the pinned rows seen so far (publish time is write-once), FACTS_TTL_MS.
 *
 * A cached fact or pin row may carry a stale conflict = 0; every decision also checks the deny set,
 * which carries conflicts within POLICY_TTL_MS. A conflict written by this isolate drops all three at once.
 */
export const POLICY_TTL_MS = 30_000;
export const FACTS_TTL_MS = 60 * 60_000;
/** Packages with more pinned rows than this are not kept in `pins` (memory). */
export const PINS_MAX_ROWS = 2_000;

export interface VersionState {
  publishTime: Date;
  conflict: boolean;
  storedAt: string | null;
  osvCheckedAt: string | null;
}

export type VersionRow = { version: string; publish_time: string; conflict: number };

export const cooldowns = new TtlCache<number>(1_000);
export const allows = new TtlCache<Set<string>>(10_000);
export const denied = new TtlCache<Set<string>>(10_000);
export const facts = new TtlCache<VersionState>(10_000);
export const pins = new TtlCache<Map<string, VersionRow>>(200);

export const pkgKey = (eco: Ecosystem, name: string) => `${eco}\u0000${name}`;

/** Test hook, and for writes in this isolate that must take effect at once (policy sync). */
export function clearDecisionCaches(): void {
  cooldowns.clear();
  allows.clear();
  denied.clear();
  facts.clear();
  pins.clear();
}

/** Drops a package's cached deny set, after this isolate blocked one of its versions. */
export function forgetDenied(eco: Ecosystem, name: string): void {
  denied.delete(pkgKey(eco, name));
}

/** After this isolate marked versions conflicted: drop everything that could still say conflict = 0. */
export function forgetConflicts(eco: Ecosystem, name: string, versions: Iterable<string>): void {
  const pkg = pkgKey(eco, name);
  denied.delete(pkg);
  pins.delete(pkg);
  for (const v of versions) facts.delete(`${pkg}\u0000${v}`);
}

/** Cached pinned rows for `versions`, or null unless every one of them is cached (absence is never cached). */
export function cachedPins(eco: Ecosystem, name: string, versions: string[], now: number): VersionRow[] | null {
  const m = pins.get(pkgKey(eco, name), now);
  if (!m) return null;
  const out: VersionRow[] = [];
  for (const v of versions) {
    const r = m.get(v);
    if (!r) return null;
    out.push(r);
  }
  return out;
}

/** Adds pinned rows read from D1 to the package's cached rows. */
export function rememberPins(eco: Ecosystem, name: string, rows: VersionRow[], now: number): void {
  if (rows.length === 0) return;
  const pkg = pkgKey(eco, name);
  const m = new Map(pins.get(pkg, now) ?? []);
  for (const r of rows) m.set(r.version, { version: r.version, publish_time: r.publish_time, conflict: r.conflict });
  if (m.size > PINS_MAX_ROWS) pins.delete(pkg);
  else pins.set(pkg, m, now, FACTS_TTL_MS);
}
