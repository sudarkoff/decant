import { ociClient } from '../oci';
import type { Deps, Env } from '../types';
import { decide } from './decide';
import type { Policy } from './schema';

const DEFAULT_COOLDOWN_DAYS = 7;
const DAY_MS = 86_400_000;
/** Registry verifications per request (each is up to 2-3 subrequests). The rest stay unverified until a later call. */
export const MAX_VERIFY = 10;

export interface ImageIn {
  /** Fully qualified repository, e.g. docker.io/library/node. */
  name: string;
  /** sha256:<64 hex>: the manifest (or index) digest written in FROM. */
  digest: string;
  /** Dockerfiles that use it (main only; shown on the dashboard). */
  files: string[];
}

/**
 * shared: the Worker confirmed the digest in a public registry; the clock is global (versions.first_seen).
 * project: anonymous pull refused or registry not supported (private image); the clock is this project's only.
 * unverified: the registry says the digest does not exist, errored, or the per-request cap was hit; no clock
 *   starts, and the digest stays in cooldown until a later call verifies it.
 */
export type Clock = 'shared' | 'project' | 'unverified';

export interface ImageDecision {
  name: string;
  digest: string;
  clock: Clock;
  /** Why the clock is not shared (registry answer), when it is not. */
  note?: string;
  /** When the clock started; null when unverified. */
  firstSeen: string | null;
  /** firstSeen + cooldown; null when unverified. */
  eligibleAt: string | null;
  /** allow: past cooldown or allowed by policy; cooldown: wait (or not yet verified); blocked: global or policy block. */
  decision: 'allow' | 'cooldown' | 'blocked';
  blocks: { source: string; reason: string }[];
}

type Row = Record<string, unknown>;
const key = (n: unknown, v: unknown) => `${String(n)}@${String(v)}`;

/**
 * Decides each image digest against the project's cooldown, the allows of main plus `ref`, and global blocks,
 * starting clocks only for what decant verified itself (never on the caller's word: a digest is just a hash,
 * and a CI token could otherwise report a digest before its image is pushed, so it would clear cooldown the
 * moment it appears). With `isMain`, also replaces the project's images-in-use set.
 */
export async function recordImages(
  env: Env,
  deps: Deps,
  projectId: string,
  ref: string,
  isMain: boolean,
  images: ImageIn[],
): Promise<{ cooldownDays: number; images: ImageDecision[] }> {
  const db = env.DB;
  const now = deps.now();
  const at = now.toISOString();
  const uniq = [...new Map(images.map((i) => [key(i.name, i.digest), i])).values()];
  const pairs = JSON.stringify(uniq.map((i) => [i.name, i.digest]));

  // 1. Clocks already started: shared (verified earlier, so immutable and never re-checked) or this project's.
  const [shared0, own0] = await db.batch<Row>([
    db.prepare(
      `SELECT v.name AS name, v.version AS version, v.first_seen AS first_seen FROM json_each(?1) j
       CROSS JOIN versions v WHERE v.eco = 'docker' AND v.name = j.value ->> 0 AND v.version = j.value ->> 1`,
    ).bind(pairs),
    db.prepare(
      `SELECT s.name AS name, s.digest AS version, s.first_seen AS first_seen FROM json_each(?2) j
       CROSS JOIN project_image_seen s WHERE s.project_id = ?1 AND s.name = j.value ->> 0 AND s.digest = j.value ->> 1`,
    ).bind(projectId, pairs),
  ]);
  const shared = new Map(shared0!.results.map((r) => [key(r.name, r.version), String(r.first_seen)]));
  const own = new Map(own0!.results.map((r) => [key(r.name, r.version), String(r.first_seen)]));

  // 2. Verify the rest in the registry, from the Worker, at most MAX_VERIFY per call.
  const clock = new Map<string, { clock: Clock; note?: string }>();
  const toShare: string[][] = [];
  const toOwn: string[][] = [];
  const oci = ociClient({ fetch: deps.fetch, timeoutMs: deps.timeoutMs });
  const pending = uniq.filter((i) => !shared.has(key(i.name, i.digest)));
  await Promise.all(
    pending.map(async (i, n) => {
      const k = key(i.name, i.digest);
      if (n >= MAX_VERIFY) {
        clock.set(k, own.has(k) ? { clock: 'project', note: 'not verified yet (too many new digests in one call)' } : { clock: 'unverified', note: 'not verified yet (too many new digests in one call); retry' });
        return;
      }
      const r = await oci.verifyDigest(i.name, i.digest);
      if (r.status === 'ok') {
        toShare.push([i.name, i.digest]);
        clock.set(k, { clock: 'shared' });
      } else if (r.status === 'denied' || r.status === 'unsupported') {
        if (!own.has(k)) toOwn.push([i.name, i.digest]);
        clock.set(k, { clock: 'project', note: r.status === 'denied' ? 'anonymous pull refused (private image?)' : 'registry not supported' });
      } else {
        // not-found (e.g. not pushed yet) or a registry error: no clock; fail closed until verified.
        clock.set(k, { clock: 'unverified', note: r.status === 'not-found' ? 'registry does not have this digest' : `registry error: ${r.message}` });
      }
    }),
  );

  // 3. One batch: start clocks, replace main's images in use, read policy, allows, blocks and the clocks.
  const stmts: D1PreparedStatement[] = [];
  if (toShare.length) {
    stmts.push(
      db.prepare(
        `INSERT OR IGNORE INTO versions (eco, name, version, publish_time, first_seen)
         SELECT 'docker', j.value ->> 0, j.value ->> 1, ?2, ?2 FROM json_each(?1) j`,
      ).bind(JSON.stringify(toShare), at),
    );
  }
  if (toOwn.length) {
    stmts.push(
      db.prepare(
        `INSERT OR IGNORE INTO project_image_seen (project_id, name, digest, first_seen)
         SELECT ?1, j.value ->> 0, j.value ->> 1, ?3 FROM json_each(?2) j`,
      ).bind(projectId, JSON.stringify(toOwn), at),
    );
  }
  if (isMain) {
    stmts.push(db.prepare('DELETE FROM project_images WHERE project_id = ?').bind(projectId));
    if (images.length > 0) {
      stmts.push(
        db.prepare(
          `INSERT OR REPLACE INTO project_images (project_id, name, digest, files, synced_at)
           SELECT ?1, j.value ->> 0, j.value ->> 1, j.value ->> 2, ?3 FROM json_each(?2) j`,
        ).bind(projectId, JSON.stringify(images.map((i) => [i.name, i.digest, JSON.stringify(i.files)])), at),
      );
    }
  }
  const reads = stmts.length;
  stmts.push(
    db.prepare(
      'SELECT p.json AS json FROM policies p JOIN projects pr ON pr.id = p.project_id AND pr.main_ref = p.ref WHERE p.project_id = ?',
    ).bind(projectId),
    db.prepare(
      `SELECT a.name AS name, a.version AS version FROM allows a JOIN projects pr ON pr.id = a.project_id
       WHERE a.project_id = ?1 AND a.ref IN (pr.main_ref, ?2) AND a.eco = 'docker'
         AND (a.advisory IS NULL OR a.verified_at IS NOT NULL)`,
    ).bind(projectId, ref),
    db.prepare(
      `SELECT b.name AS name, b.version AS version, b.source AS source, b.reason AS reason FROM json_each(?1) j
       CROSS JOIN global_blocks b WHERE b.eco = 'docker' AND b.name = j.value ->> 0 AND b.version = j.value ->> 1
       ORDER BY b.source`,
    ).bind(pairs),
    // Re-read the clocks just written: a concurrent call may have started one first (first write wins).
    db.prepare(
      `SELECT v.name AS name, v.version AS version, v.first_seen AS first_seen FROM json_each(?1) j
       CROSS JOIN versions v WHERE v.eco = 'docker' AND v.name = j.value ->> 0 AND v.version = j.value ->> 1`,
    ).bind(JSON.stringify(toShare)),
    db.prepare(
      `SELECT s.name AS name, s.digest AS version, s.first_seen AS first_seen FROM json_each(?2) j
       CROSS JOIN project_image_seen s WHERE s.project_id = ?1 AND s.name = j.value ->> 0 AND s.digest = j.value ->> 1`,
    ).bind(projectId, JSON.stringify(toOwn)),
  );
  const res = await db.batch<Row>(stmts);
  const [pol, allows, blocks, sharedNew, ownNew] = res.slice(reads) as D1Result<Row>[];
  for (const r of sharedNew!.results) shared.set(key(r.name, r.version), String(r.first_seen));
  for (const r of ownNew!.results) own.set(key(r.name, r.version), String(r.first_seen));
  const json = pol!.results[0]?.json as string | undefined;
  const cooldownDays = json ? (JSON.parse(json) as Policy).cooldownDays : DEFAULT_COOLDOWN_DAYS;
  const allowed = new Set(allows!.results.map((r) => key(r.name, r.version)));
  const blockedBy = new Map<string, { source: string; reason: string }[]>();
  for (const r of blocks!.results) {
    const k = key(r.name, r.version);
    blockedBy.set(k, [...(blockedBy.get(k) ?? []), { source: String(r.source), reason: String(r.reason) }]);
  }

  return {
    cooldownDays,
    images: uniq.map((i): ImageDecision => {
      const k = key(i.name, i.digest);
      const c = shared.has(k) ? { clock: 'shared' as const } : (clock.get(k) ?? { clock: 'unverified' as const });
      const seen = c.clock === 'shared' ? shared.get(k)! : c.clock === 'project' ? (own.get(k) ?? null) : null;
      const fs = seen === null ? null : new Date(seen);
      const b = blockedBy.get(k) ?? [];
      const d = decide({ publishTime: fs, conflict: false, blocked: b.length > 0, allowed: allowed.has(k), cooldownDays, now });
      return {
        name: i.name,
        digest: i.digest,
        clock: c.clock,
        ...('note' in c && c.note ? { note: c.note } : {}),
        firstSeen: fs?.toISOString() ?? null,
        eligibleAt: fs ? new Date(fs.getTime() + cooldownDays * DAY_MS).toISOString() : null,
        decision: d === 'hidden' ? 'cooldown' : d,
        blocks: b,
      };
    }),
  };
}
