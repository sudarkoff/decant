import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handleDashboardApi } from '../src/dashboard/api';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock } from './helpers';

const deps: Deps = { fetch: fakeFetch({}), now: fixedClock('2026-11-19T12:00:00Z') };
let e: Env;

async function freshness(project: string): Promise<any> {
  const res = await handleDashboardApi(new Request(`https://h/dashboard/api/freshness?project=${project}&range=7`), e, deps, 'freshness');
  expect(res.status).toBe(200);
  return res.json();
}

async function exec(sql: string, ...rows: unknown[][]): Promise<void> {
  await e.DB.batch(rows.map((r) => e.DB.prepare(sql).bind(...r)));
}

const d = (eco: string, name: string, version: string, direct: boolean, via: string[] = []) => ({ eco, name, version, direct, via });

describe('freshness: direct vs transitive', () => {
  beforeAll(async () => {
    e = env as unknown as Env;
    await exec('INSERT INTO projects (id, created_at) VALUES (?, ?)', ['fa', '2026-01-01T00:00:00Z'], ['fb', '2026-01-01T00:00:00Z']);
    await exec(
      'INSERT INTO serve_log (project_id, eco, name, version, day) VALUES (?, ?, ?, ?, ?)',
      ['fa', 'npm', 'react', '17.0.0', '2026-11-19'],
      ['fa', 'npm', 'glob', '7.2.0', '2026-11-19'],
      ['fa', 'npm', 'unlisted', '1.0.0', '2026-11-19'],
      ['fa', 'go', 'example.com/m', 'v1.0.0', '2026-11-19'],
      ['fb', 'npm', 'glob', '7.2.0', '2026-11-19'],
    );
    await exec(
      'INSERT INTO packages (eco, name, latest, checked_at) VALUES (?, ?, ?, ?)',
      ['npm', 'react', '19.0.0', 'x'],
      ['npm', 'glob', '11.0.0', 'x'],
      ['npm', 'unlisted', '2.0.0', 'x'],
      ['go', 'example.com/m', 'v1.0.0', 'x'],
      ['go', 'example.com/m/v3', 'v3.0.0', 'x'],
    );
    await exec(
      'INSERT INTO project_deps (project_id, sha, synced_at, json) VALUES (?, ?, ?, ?)',
      [
        'fa',
        's',
        '2026-11-19T00:00:00Z',
        JSON.stringify([
          d('npm', 'react', '18.0.0', true), // direct at another version: still direct (version-insensitive)
          d('npm', 'glob', '7.2.0', false, ['rimraf', 'jest']),
          d('npm', 'glob', '8.0.0', false, ['jest', 'eslint']),
          d('go', 'example.com/m', 'v1.0.0', false),
        ]),
      ],
    );
  });

  it('splits by the synced summary; transitive lists who holds it back', async () => {
    const body = await freshness('fa');
    expect(body.majorBehind.direct).toEqual([{ project: 'fa', package: 'npm:react', version: '17.0.0', latest: '19.0.0', classified: true }]);
    expect(body.majorBehind.transitive).toEqual([
      { project: 'fa', package: 'go:example.com/m', version: 'v1.0.0', latest: 'v3.0.0', via: [] },
      { project: 'fa', package: 'npm:glob', version: '7.2.0', latest: '11.0.0', via: ['eslint', 'jest', 'rimraf'] },
      // served but absent from the summary: not direct
      { project: 'fa', package: 'npm:unlisted', version: '1.0.0', latest: '2.0.0', via: [] },
    ]);
    expect(body.transitiveMajorBehindCount).toBe(3);
  });

  it('a project without a summary stays unclassified (listed as direct)', async () => {
    const body = await freshness('fb');
    expect(body.majorBehind).toEqual({
      direct: [{ project: 'fb', package: 'npm:glob', version: '7.2.0', latest: '11.0.0', classified: false }],
      transitive: [],
    });
    expect(body.transitiveMajorBehindCount).toBe(0);
  });

  it('all: each project classified by its own summary', async () => {
    const body = await freshness('all');
    expect(body.majorBehind.direct).toEqual([
      { project: 'fb', package: 'npm:glob', version: '7.2.0', latest: '11.0.0', classified: false },
      { project: 'fa', package: 'npm:react', version: '17.0.0', latest: '19.0.0', classified: true },
    ]);
    expect(body.majorBehind.transitive.map((x: { project: string; package: string }) => `${x.project} ${x.package}`)).toEqual([
      'fa go:example.com/m',
      'fa npm:glob',
      'fa npm:unlisted',
    ]);
    expect(body.transitiveMajorBehindCount).toBe(3);
  });

  it('a corrupt summary row is treated as missing', async () => {
    await exec('INSERT INTO project_deps (project_id, sha, synced_at, json) VALUES (?, ?, ?, ?)', ['fb', 's', 'x', 'not json']);
    expect((await freshness('fb')).majorBehind.direct[0].classified).toBe(false);
  });
});
