import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import {
  addGlobalBlock,
  blockedVersions,
  getPinnedTimes,
  getVersionState,
  loadPolicyView,
  logServe,
  markOsvChecked,
  markStored,
  pinPublishTimes,
} from '../src/policy/store';
import type { Env, PackageRef } from '../src/types';

const e = env as unknown as Env;
const T1 = new Date('2026-01-01T00:00:00.000Z');
const T2 = new Date('2026-02-01T00:00:00.000Z');
const NOW = new Date('2026-11-19T00:00:00.000Z');

describe('publish-time pinning', () => {
  it('pins the first time and flags a later differing time as a conflict', async () => {
    const first = await pinPublishTimes(e, 'npm', 'pin-a', new Map([['1.0.0', T1], ['1.1.0', T2]]), NOW);
    expect(first.get('1.0.0')).toEqual({ publishTime: T1, conflict: false });
    expect(first.get('1.1.0')).toEqual({ publishTime: T2, conflict: false });

    const again = await pinPublishTimes(e, 'npm', 'pin-a', new Map([['1.0.0', T2], ['1.1.0', T2]]), NOW);
    expect(again.get('1.0.0')).toEqual({ publishTime: T1, conflict: true });
    expect(again.get('1.1.0')).toEqual({ publishTime: T2, conflict: false });

    const pinned = await getPinnedTimes(e, 'npm', 'pin-a', ['1.0.0', '9.9.9']);
    expect(pinned.get('1.0.0')).toEqual({ publishTime: T1, conflict: true });
    expect(pinned.has('9.9.9')).toBe(false);
  });

  it('is scoped by ecosystem and name', async () => {
    await pinPublishTimes(e, 'npm', 'pin-b', new Map([['1.0.0', T1]]), NOW);
    const go = await pinPublishTimes(e, 'go', 'pin-b', new Map([['1.0.0', T2]]), NOW);
    expect(go.get('1.0.0')).toEqual({ publishTime: T2, conflict: false });
  });

  it('handles empty input', async () => {
    expect((await pinPublishTimes(e, 'npm', 'pin-c', new Map(), NOW)).size).toBe(0);
    expect((await getPinnedTimes(e, 'npm', 'pin-c', [])).size).toBe(0);
  });
});

describe('version state', () => {
  it('tracks stored_at and osv_checked_at', async () => {
    const ref: PackageRef = { eco: 'go', name: 'github.com/s/t', version: 'v1.0.0' };
    expect(await getVersionState(e, ref)).toBeNull();
    await pinPublishTimes(e, 'go', ref.name, new Map([[ref.version, T1]]), NOW);
    expect(await getVersionState(e, ref)).toEqual({ publishTime: T1, conflict: false, storedAt: null, osvCheckedAt: null });
    await markStored(e, ref, NOW);
    await markOsvChecked(e, [ref, { eco: 'npm', name: 'missing', version: '1.0.0' }], T2);
    expect(await getVersionState(e, ref)).toEqual({
      publishTime: T1,
      conflict: false,
      storedAt: NOW.toISOString(),
      osvCheckedAt: T2.toISOString(),
    });
  });
});

describe('blocks and serve log', () => {
  it('global blocks from any source show up in blockedVersions', async () => {
    await addGlobalBlock(e, { eco: 'npm', name: 'blk', version: '1.0.0' }, 'verdict:guarddog', 'bad', NOW);
    await addGlobalBlock(e, { eco: 'npm', name: 'blk', version: '1.0.0' }, 'osv', 'MAL-2025-1', NOW);
    await addGlobalBlock(e, { eco: 'npm', name: 'blk', version: '2.0.0' }, 'osv', 'MAL-2025-2', NOW);
    expect(await blockedVersions(e, 'npm', 'blk')).toEqual(new Set(['1.0.0', '2.0.0']));
    expect(await blockedVersions(e, 'go', 'blk')).toEqual(new Set());
  });

  it('logServe records one row per day', async () => {
    const ref: PackageRef = { eco: 'npm', name: 'served', version: '1.0.0' };
    await logServe(e, 'p', ref, NOW);
    await logServe(e, 'p', ref, new Date('2026-11-19T23:00:00Z'));
    const r = await e.DB.prepare("SELECT day FROM serve_log WHERE name = 'served'").all<{ day: string }>();
    expect(r.results).toEqual([{ day: '2026-11-19' }]);
  });
});

describe('loadPolicyView', () => {
  it('defaults when no policy exists', async () => {
    const v = await loadPolicyView(e, 'nobody', null, 'npm', 'x');
    expect(v.cooldownDays).toBe(7);
    expect(v.allowed).toEqual(new Set());
  });

  it('ignores unverified advisory rows', async () => {
    await e.DB.batch([
      e.DB.prepare("INSERT INTO projects (id, created_at) VALUES ('lv', 'x')"),
      e.DB.prepare(
        "INSERT INTO policies VALUES ('lv', 'main', ?, 'sha', 'x')",
      ).bind(JSON.stringify({ project: 'lv', cooldownDays: 3, autoShip: {}, allow: [], block: [] })),
      e.DB.prepare("INSERT INTO allows VALUES ('lv','main','npm','a','1.0.0',NULL,'r',NULL)"),
      e.DB.prepare("INSERT INTO allows VALUES ('lv','main','npm','a','2.0.0','GHSA-aaaa-bbbb-cccc','r',NULL)"),
      e.DB.prepare("INSERT INTO allows VALUES ('lv','main','npm','a','3.0.0','GHSA-aaaa-bbbb-cccc','r','x')"),
      e.DB.prepare("INSERT INTO allows VALUES ('lv','main','npm','b','1.0.0',NULL,'r',NULL)"),
      e.DB.prepare("INSERT INTO allows VALUES ('lv','main','go','a','1.5.0',NULL,'r',NULL)"),
    ]);
    const v = await loadPolicyView(e, 'lv', null, 'npm', 'a');
    expect(v.cooldownDays).toBe(3);
    expect(v.allowed).toEqual(new Set(['1.0.0', '3.0.0']));
  });

  it('includes the overlay ref and is scoped to one package', async () => {
    await e.DB.batch([
      e.DB.prepare("INSERT INTO allows VALUES ('lv','pr-9','npm','a','4.0.0',NULL,'r',NULL)"),
      e.DB.prepare("INSERT INTO allows VALUES ('lv','pr-8','npm','a','5.0.0',NULL,'r',NULL)"),
    ]);
    expect((await loadPolicyView(e, 'lv', 'pr-9', 'npm', 'a')).allowed).toEqual(new Set(['1.0.0', '3.0.0', '4.0.0']));
    expect((await loadPolicyView(e, 'lv', null, 'npm', 'b')).allowed).toEqual(new Set(['1.0.0']));
    expect((await loadPolicyView(e, 'lv', null, 'go', 'a')).allowed).toEqual(new Set(['1.5.0']));
  });
});
