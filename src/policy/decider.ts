import type { RequestCtx } from '../auth';
import { TtlCache } from '../cache';
import type { Deps, Ecosystem, Env } from '../types';
import { decide, type Decision } from './decide';
import type { Policy } from './schema';
import type { PinnedTime } from './store';

/*
 * Decision inputs, read in one D1 round trip and cached per isolate.
 *
 * - Policy view (cooldown + the ref's allows), per project and ref: POLICY_TTL_MS.
 * - Deny set (global blocks + publish-time conflicts), per package: POLICY_TTL_MS. A new block or conflict
 *   therefore reaches every request within 30 s. A first serve (a version not yet stored, about to be
 *   fetched upstream) always reads the deny set fresh.
 * - Version facts (pinned publish time, stored_at), per version: FACTS_TTL_MS. Both are write-once.
 *   Conflict is never taken from a cached row alone: the deny set (≤ 30 s) carries it.
 *
 * Nothing absent is cached as "allowed": a missing version row is re-read every time, and an unknown
 * project has no view to cache beyond the default cooldown. If the reads fail (after d1-retry's retries)
 * the error propagates and the request fails closed.
 */
export const POLICY_TTL_MS = 30_000;
export const FACTS_TTL_MS = 60 * 60_000;
const DEFAULT_COOLDOWN_DAYS = 7;

interface View {
  cooldownDays: number;
  /** `${eco}\0${name}\0${version}` */
  allowed: Set<string>;
}

export interface VersionState {
  publishTime: Date;
  conflict: boolean;
  storedAt: string | null;
  osvCheckedAt: string | null;
}

const views = new TtlCache<View>(1_000);
const denied = new TtlCache<Set<string>>(10_000);
const facts = new TtlCache<VersionState>(10_000);

/** Test hook, and for writes in this isolate that must take effect at once (policy sync). */
export function clearDecisionCaches(): void {
  views.clear();
  denied.clear();
  facts.clear();
}

/** Drops a package's cached deny set, after this isolate blocked one of its versions. */
export function forgetDenied(eco: Ecosystem, name: string): void {
  denied.delete(`${eco}\u0000${name}`);
}

export interface Loaded<T> {
  decide: (version: string, pin: PinnedTime | null | undefined) => Decision;
  /** The requested version's state, or null if it has never been pinned (only with opts.version). */
  state: VersionState | null;
  /** The result of opts.extra, read in the same round trip. */
  extra: D1Result<T> | null;
}

export interface LoadOpts {
  /** Also load this version's state. */
  version?: string;
  /** The caller serves a stored copy when stored_at is set: a cached state without it is re-read. */
  needStored?: boolean;
  /** One more read to run in the same batch (e.g. the package's pinned times). */
  extra?: D1PreparedStatement;
}

type Row = Record<string, unknown>;

/** Everything one request needs to decide on `eco`/`name`, in at most one D1 round trip. */
export async function loadDecision<T = Row>(
  env: Env,
  deps: Deps,
  rc: RequestCtx,
  eco: Ecosystem,
  name: string,
  opts: LoadOpts = {},
): Promise<Loaded<T>> {
  const now = deps.now();
  const t = now.getTime();
  const pkg = `${eco}\u0000${name}`;
  const viewKey = `${rc.projectId}\u0000${rc.ref ?? ''}`;
  const factKey = opts.version === undefined ? null : `${pkg}\u0000${opts.version}`;

  let view = views.get(viewKey, t);
  let state: VersionState | null | undefined;
  if (factKey) {
    const f = facts.get(factKey, t);
    if (f && (!opts.needStored || f.storedAt)) state = f;
  }
  // About to serve a version for the first time (or re-fetch it): no cached deny set.
  const firstServe = opts.needStored && state === undefined;
  let deny = firstServe ? undefined : denied.get(pkg, t);

  const db = env.DB;
  const stmts: D1PreparedStatement[] = [];
  const at = { view: -1, deny: -1, state: -1, extra: -1 };
  if (!view) {
    at.view = stmts.length;
    stmts.push(
      db.prepare(
        'SELECT p.json AS json FROM policies p JOIN projects pr ON pr.id = p.project_id AND pr.main_ref = p.ref WHERE p.project_id = ?',
      ).bind(rc.projectId),
      // Advisory rows count only once verified.
      db.prepare(
        `SELECT a.eco AS eco, a.name AS name, a.version AS version FROM allows a JOIN projects pr ON pr.id = a.project_id
         WHERE a.project_id = ?1 AND a.ref IN (pr.main_ref, ?2) AND (a.advisory IS NULL OR a.verified_at IS NOT NULL)`,
      ).bind(rc.projectId, rc.ref),
    );
  }
  if (!deny) {
    at.deny = stmts.length;
    // Both halves are index probes: idx_blocks_pkg, and the partial idx_versions_conflict.
    stmts.push(
      db.prepare(
        `SELECT version FROM global_blocks WHERE eco = ?1 AND name = ?2
         UNION SELECT version FROM versions WHERE eco = ?1 AND name = ?2 AND conflict = 1`,
      ).bind(eco, name),
    );
  }
  if (factKey && state === undefined) {
    at.state = stmts.length;
    stmts.push(
      db.prepare('SELECT publish_time, conflict, stored_at, osv_checked_at FROM versions WHERE eco = ? AND name = ? AND version = ?').bind(
        eco,
        name,
        opts.version,
      ),
    );
  }
  if (opts.extra) {
    at.extra = stmts.length;
    stmts.push(opts.extra);
  }

  let extra: D1Result<T> | null = null;
  if (stmts.length > 0) {
    const res = await db.batch<Row>(stmts);
    if (at.view >= 0) {
      const json = res[at.view]!.results[0]?.json as string | undefined;
      const allowed = new Set(
        (res[at.view + 1]!.results as { eco: string; name: string; version: string }[]).map(
          (r) => `${r.eco}\u0000${r.name}\u0000${r.version}`,
        ),
      );
      view = { cooldownDays: json ? (JSON.parse(json) as Policy).cooldownDays : DEFAULT_COOLDOWN_DAYS, allowed };
      views.set(viewKey, view, t, POLICY_TTL_MS);
    }
    if (at.deny >= 0) {
      deny = new Set((res[at.deny]!.results as { version: string }[]).map((r) => r.version));
      denied.set(pkg, deny, t, POLICY_TTL_MS);
    }
    if (at.state >= 0) {
      const r = res[at.state]!.results[0] as
        | { publish_time: string; conflict: number; stored_at: string | null; osv_checked_at: string | null }
        | undefined;
      state = r
        ? { publishTime: new Date(r.publish_time), conflict: r.conflict === 1, storedAt: r.stored_at, osvCheckedAt: r.osv_checked_at }
        : null;
      if (state) facts.set(factKey!, state, t, FACTS_TTL_MS);
    }
    if (at.extra >= 0) extra = res[at.extra] as unknown as D1Result<T>;
  }

  const v = view!;
  const d = deny!;
  return {
    decide: (version, pin) =>
      decide({
        publishTime: pin?.publishTime ?? null,
        conflict: pin?.conflict ?? false,
        blocked: d.has(version),
        allowed: v.allowed.has(`${pkg}\u0000${version}`),
        cooldownDays: v.cooldownDays,
        now,
      }),
    state: state ?? null,
    extra,
  };
}

/** Loads the decision inputs for a package; returns a per-version decision function. */
export async function decider(env: Env, deps: Deps, rc: RequestCtx, eco: Ecosystem, name: string) {
  return (await loadDecision(env, deps, rc, eco, name)).decide;
}
