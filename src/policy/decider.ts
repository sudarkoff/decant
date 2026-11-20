import type { RequestCtx } from '../auth';
import type { Deps, Ecosystem, Env } from '../types';
import {
  allows,
  cachedPins,
  cooldowns,
  denied,
  facts,
  FACTS_TTL_MS,
  pkgKey,
  POLICY_TTL_MS,
  rememberPins,
  type VersionRow,
  type VersionState,
} from './caches';
import { decide, type Decision } from './decide';
import type { Policy } from './schema';
import { selectPinnedStmt, type PinnedTime } from './store';

export { clearDecisionCaches, FACTS_TTL_MS, forgetDenied, POLICY_TTL_MS, type VersionState } from './caches';

/*
 * Decision inputs, read in one D1 round trip and cached per isolate (caches.ts).
 *
 * - Cooldown per project+ref, and that ref's allows for the one package: POLICY_TTL_MS.
 * - Deny set (global blocks + publish-time conflicts), per package: POLICY_TTL_MS. A new block or conflict
 *   therefore reaches every request within 30 s. A first serve (a version not yet stored, about to be
 *   fetched upstream) always reads the deny set fresh.
 * - Version facts (pinned publish time, stored_at) and pinned rows: FACTS_TTL_MS. Publish time and
 *   stored_at are write-once; conflict is never taken from a cached row alone: the deny set carries it.
 *
 * Nothing absent is cached as "allowed": a missing version row is re-read every time. If the reads fail
 * (after d1-retry's retries) the error propagates and the request fails closed.
 */
const DEFAULT_COOLDOWN_DAYS = 7;

export interface Loaded {
  decide: (version: string, pin: PinnedTime | null | undefined) => Decision;
  /** The requested version's state, or null if it has never been pinned (only with opts.version). */
  state: VersionState | null;
  /** Pinned rows among opts.pins (only with opts.pins). */
  pinRows: VersionRow[];
}

export interface LoadOpts {
  /** Also load this version's state. */
  version?: string;
  /** The caller serves a stored copy when stored_at is set: a cached state without it is re-read. */
  needStored?: boolean;
  /** Also load the pinned rows of these versions. */
  pins?: string[];
}

type Row = Record<string, unknown>;

/** Everything one request needs to decide on `eco`/`name`, in at most one D1 round trip. */
export async function loadDecision(
  env: Env,
  deps: Deps,
  rc: RequestCtx,
  eco: Ecosystem,
  name: string,
  opts: LoadOpts = {},
): Promise<Loaded> {
  const now = deps.now();
  const t = now.getTime();
  const pkg = pkgKey(eco, name);
  const refKey = `${rc.projectId}\u0000${rc.ref ?? ''}`;
  const allowKey = `${refKey}\u0000${pkg}`;
  const factKey = opts.version === undefined ? null : `${pkg}\u0000${opts.version}`;

  let cooldown = cooldowns.get(refKey, t);
  let allowed = allows.get(allowKey, t);
  let state: VersionState | null | undefined;
  if (factKey) {
    const f = facts.get(factKey, t);
    if (f && (!opts.needStored || f.storedAt)) state = f;
  }
  // About to serve a version for the first time (or re-fetch it): no cached deny set.
  const firstServe = opts.needStored && state === undefined;
  let deny = firstServe ? undefined : denied.get(pkg, t);
  const wanted = opts.pins ?? [];
  let pinRows = wanted.length > 0 ? cachedPins(eco, name, wanted, t) : [];

  const db = env.DB;
  const stmts: D1PreparedStatement[] = [];
  const at = { cooldown: -1, allowed: -1, deny: -1, state: -1, pins: -1 };
  if (cooldown === undefined) {
    at.cooldown = stmts.length;
    stmts.push(
      db.prepare(
        'SELECT p.json AS json FROM policies p JOIN projects pr ON pr.id = p.project_id AND pr.main_ref = p.ref WHERE p.project_id = ?',
      ).bind(rc.projectId),
    );
  }
  if (!allowed) {
    at.allowed = stmts.length;
    // Main-ref allows plus the ref's, for this package only (a primary-key range). Advisory rows count once verified.
    stmts.push(
      db.prepare(
        `SELECT a.version AS version FROM allows a JOIN projects pr ON pr.id = a.project_id
         WHERE a.project_id = ?1 AND a.ref IN (pr.main_ref, ?2) AND a.eco = ?3 AND a.name = ?4
           AND (a.advisory IS NULL OR a.verified_at IS NOT NULL)`,
      ).bind(rc.projectId, rc.ref, eco, name),
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
  if (pinRows === null) {
    at.pins = stmts.length;
    stmts.push(selectPinnedStmt(env, eco, name, wanted));
  }

  if (stmts.length > 0) {
    const res = await db.batch<Row>(stmts);
    if (at.cooldown >= 0) {
      const json = res[at.cooldown]!.results[0]?.json as string | undefined;
      cooldown = json ? (JSON.parse(json) as Policy).cooldownDays : DEFAULT_COOLDOWN_DAYS;
      cooldowns.set(refKey, cooldown, t, POLICY_TTL_MS);
    }
    if (at.allowed >= 0) {
      allowed = new Set((res[at.allowed]!.results as { version: string }[]).map((r) => r.version));
      allows.set(allowKey, allowed, t, POLICY_TTL_MS);
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
    if (at.pins >= 0) {
      const rows = res[at.pins]!.results as VersionRow[];
      rememberPins(eco, name, rows, t); // a long list reads the whole package: keep all of it
      const want = new Set(wanted);
      pinRows = rows.filter((r) => want.has(r.version));
    }
  }

  const cd = cooldown!;
  const a = allowed!;
  const d = deny!;
  return {
    decide: (version, pin) =>
      decide({
        publishTime: pin?.publishTime ?? null,
        conflict: pin?.conflict ?? false,
        blocked: d.has(version),
        allowed: a.has(version),
        cooldownDays: cd,
        now,
      }),
    state: state ?? null,
    pinRows: pinRows ?? [],
  };
}

/** Loads the decision inputs for a package; returns a per-version decision function. */
export async function decider(env: Env, deps: Deps, rc: RequestCtx, eco: Ecosystem, name: string) {
  return (await loadDecision(env, deps, rc, eco, name)).decide;
}
