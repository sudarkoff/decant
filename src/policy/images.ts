import type { Env } from '../types';
import { decide } from './decide';
import type { Policy } from './schema';

const DEFAULT_COOLDOWN_DAYS = 7;
const DAY_MS = 86_400_000;

export interface ImageIn {
  /** Fully qualified repository, e.g. docker.io/library/node. */
  name: string;
  /** sha256:<64 hex>: the manifest (or index) digest written in FROM. */
  digest: string;
  /** Dockerfiles that use it (main only; shown on the dashboard). */
  files: string[];
}

export interface ImageDecision {
  name: string;
  digest: string;
  /** When decant first saw this digest (any project, any ref): the cooldown clock. */
  firstSeen: string;
  /** firstSeen + cooldown. */
  eligibleAt: string;
  /** allow: past cooldown or allowed by policy; cooldown: wait until eligibleAt; blocked: global or policy block. */
  decision: 'allow' | 'cooldown' | 'blocked';
  blocks: { source: string; reason: string }[];
}

type Row = Record<string, unknown>;

/**
 * Records first-seen for every image digest (first write wins, shared across projects) and decides each
 * against the project's cooldown, the allows of main plus `ref`, and global blocks. With `isMain`, also
 * replaces the project's images-in-use set. One D1 batch, a fixed number of statements whatever the size.
 */
export async function recordImages(env: Env, projectId: string, ref: string, isMain: boolean, images: ImageIn[], now: Date): Promise<{ cooldownDays: number; images: ImageDecision[] }> {
  const db = env.DB;
  const at = now.toISOString();
  const pairs = JSON.stringify(images.map((i) => [i.name, i.digest]));
  const stmts: D1PreparedStatement[] = [];
  if (images.length > 0) {
    stmts.push(
      db.prepare(
        `INSERT OR IGNORE INTO versions (eco, name, version, publish_time, first_seen)
         SELECT 'docker', j.value ->> 0, j.value ->> 1, ?2, ?2 FROM json_each(?1) j`,
      ).bind(pairs, at),
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
    // CROSS JOIN keeps json_each the outer loop: one primary-key probe per image.
    db.prepare(
      `SELECT v.name AS name, v.version AS version, v.first_seen AS first_seen FROM json_each(?1) j
       CROSS JOIN versions v WHERE v.eco = 'docker' AND v.name = j.value ->> 0 AND v.version = j.value ->> 1`,
    ).bind(pairs),
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
  );
  const res = await db.batch<Row>(stmts);
  const [pol, seen, allows, blocks] = res.slice(reads) as D1Result<Row>[];
  const json = pol!.results[0]?.json as string | undefined;
  const cooldownDays = json ? (JSON.parse(json) as Policy).cooldownDays : DEFAULT_COOLDOWN_DAYS;
  const key = (n: unknown, v: unknown) => `${String(n)}@${String(v)}`;
  const firstSeen = new Map(seen!.results.map((r) => [key(r.name, r.version), String(r.first_seen)]));
  const allowed = new Set(allows!.results.map((r) => key(r.name, r.version)));
  const blockedBy = new Map<string, { source: string; reason: string }[]>();
  for (const r of blocks!.results) {
    const k = key(r.name, r.version);
    blockedBy.set(k, [...(blockedBy.get(k) ?? []), { source: String(r.source), reason: String(r.reason) }]);
  }
  const out: ImageDecision[] = [];
  const done = new Set<string>();
  for (const i of images) {
    const k = key(i.name, i.digest);
    if (done.has(k)) continue;
    done.add(k);
    const fs = new Date(firstSeen.get(k) ?? at);
    const b = blockedBy.get(k) ?? [];
    const d = decide({ publishTime: fs, conflict: false, blocked: b.length > 0, allowed: allowed.has(k), cooldownDays, now });
    out.push({
      name: i.name,
      digest: i.digest,
      firstSeen: fs.toISOString(),
      eligibleAt: new Date(fs.getTime() + cooldownDays * DAY_MS).toISOString(),
      decision: d === 'hidden' ? 'cooldown' : d,
      blocks: b,
    });
  }
  return { cooldownDays, images: out };
}
