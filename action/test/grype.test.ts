import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { GRYPE_SHA256, GRYPE_VERSION, grypeArch, grypeEnv, grypeUrl, grypeVerdict, installGrype, normalizeGrypeDetails, parseGrypeJson, scanImage } from '../src/grype';
import { fakeExec, fakeFetch, memFs } from './fakes';

const D = `sha256:${'a'.repeat(64)}`;

const match = (id: string, severity: string, pkg: string, version: string, fix?: { state: string; versions: string[] }) => ({
  vulnerability: { id, severity, fix: fix ?? { state: 'not-fixed', versions: [] } },
  artifact: { name: pkg, version, type: 'deb' },
});

describe('grype install', () => {
  it('pins 0.121.3 for linux amd64 and arm64', () => {
    expect(GRYPE_VERSION).toBe('0.121.3');
    expect(GRYPE_SHA256.amd64).toMatch(/^[0-9a-f]{64}$/);
    expect(grypeUrl('arm64')).toBe('https://github.com/anchore/grype/releases/download/v0.121.3/grype_0.121.3_linux_arm64.tar.gz');
    expect(grypeArch('linux', 'x64')).toBe('amd64');
    expect(grypeArch('linux', 'arm64')).toBe('arm64');
    expect(() => grypeArch('darwin', 'arm64')).toThrow(/Linux runners only/);
    expect(() => grypeArch('linux', 'ia32')).toThrow(/no pinned Grype build/);
  });

  it('verifies the checksum before extracting only the binary', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const sum = createHash('sha256').update(bytes).digest('hex');
    const f = fakeFetch((c) => (c.url === grypeUrl('amd64') ? new Response(bytes) : undefined));
    const exec = fakeExec();
    const fs = memFs();
    expect(await installGrype(f, exec, fs, '/rt/grype', 'amd64', { amd64: sum, arm64: 'x' })).toEqual({ bin: '/rt/grype/grype' });
    expect(fs.bytes.get('/rt/grype/grype.tar.gz')).toEqual(bytes);
    expect(exec.calls).toEqual([{ cmd: 'tar', args: ['-xzf', '/rt/grype/grype.tar.gz', '-C', '/rt/grype', 'grype'], opts: undefined }]);
  });

  it('a checksum mismatch throws and nothing is written or extracted', async () => {
    const f = fakeFetch(() => new Response(new Uint8Array([9])));
    const exec = fakeExec();
    const fs = memFs();
    await expect(installGrype(f, exec, fs, '/rt/grype', 'amd64')).rejects.toThrow(/checksum mismatch/);
    expect(exec.calls).toEqual([]);
    expect(fs.bytes.size).toBe(0);
  });

  it('a failed download throws', async () => {
    const f = fakeFetch(() => new Response('nope', { status: 404 }));
    await expect(installGrype(f, fakeExec(), memFs(), '/rt/g', 'arm64')).rejects.toThrow(/HTTP 404/);
  });
});

describe('grype scan', () => {
  it('fails closed on database problems and caches the DB under the given dir', () => {
    expect(grypeEnv('/rt/grype-db')).toEqual({
      GRYPE_DB_CACHE_DIR: '/rt/grype-db',
      GRYPE_DB_AUTO_UPDATE: 'true',
      GRYPE_DB_REQUIRE_UPDATE_CHECK: 'true',
      GRYPE_DB_VALIDATE_AGE: 'true',
      GRYPE_CHECK_FOR_APP_UPDATE: 'false',
    });
  });

  it('scans registry:<repo>@<digest> as JSON, with a literal linux platform only', async () => {
    const exec = fakeExec(() => ({ stdout: JSON.stringify({ matches: [] }) }));
    await scanImage(exec, '/g/grype', 'docker.io/library/node', D, { A: 'b' }, 'linux/arm64');
    await scanImage(exec, '/g/grype', 'docker.io/library/node', D, { A: 'b' }, '$BUILDPLATFORM');
    expect(exec.calls[0]).toEqual({ cmd: '/g/grype', args: [`registry:docker.io/library/node@${D}`, '-o', 'json', '-q', '--platform', 'linux/arm64'], opts: { env: { A: 'b' } } });
    expect(exec.calls[1]!.args).toEqual([`registry:docker.io/library/node@${D}`, '-o', 'json', '-q']);
  });

  it('a non-zero exit (e.g. the DB update check failed) is a scan error', async () => {
    const exec = fakeExec(() => ({ code: 1, stderr: 'failed to load vulnerability db: unable to check for update' }));
    await expect(scanImage(exec, '/g', 'docker.io/library/node', D, {})).rejects.toThrow(/grype exited 1: failed to load vulnerability db/);
  });

  it('maps severities case-insensitively; High/Critical with a fix fail, without a fix are reported', () => {
    const r = parseGrypeJson(
      JSON.stringify({
        matches: [
          match('CVE-2026-1', 'Critical', 'openssl', '3.0.11', { state: 'fixed', versions: ['3.0.15'] }),
          match('CVE-2026-2', 'HIGH', 'zlib', '1.2', { state: 'not-fixed', versions: [] }),
          match('CVE-2026-3', 'Medium', 'curl', '8.0', { state: 'fixed', versions: ['8.1'] }),
          match('CVE-2026-4', 'Negligible', 'bash', '5'),
          match('CVE-2026-5', 'weird', 'x', '1'),
          match('CVE-2026-6', 'High', 'glibc', '2.36', { state: 'wont-fix', versions: ['2.37'] }),
        ],
      }),
    );
    expect(r.findings.map((f) => [f.id, f.severity])).toEqual([
      ['CVE-2026-1', 'critical'],
      ['CVE-2026-2', 'high'],
      ['CVE-2026-6', 'high'],
      ['CVE-2026-3', 'moderate'],
      ['CVE-2026-5', 'unknown'],
      ['CVE-2026-4', 'low'],
    ]);
    expect(r.failing.map((f) => f.id)).toEqual(['CVE-2026-1']);
    expect(r.unfixed.map((f) => f.id)).toEqual(['CVE-2026-2', 'CVE-2026-6']); // wont-fix is not a fix
    expect(grypeVerdict(r)).toEqual({ result: 'flagged', details: [r.findings[0], r.findings[1], r.findings[2]] });
    expect(grypeVerdict(parseGrypeJson('{"matches":[]}'))).toEqual({ result: 'clean', details: [] });
  });

  it('an incomplete report is never clean', () => {
    expect(() => parseGrypeJson('not json')).toThrow(/invalid JSON/);
    expect(() => parseGrypeJson('{}')).toThrow(/no matches/);
    expect(() => parseGrypeJson('{"matches":[{"artifact":{}}]}')).toThrow(/no vulnerability id/);
  });

  it('normalizes cached details written by another project', () => {
    expect(
      normalizeGrypeDetails([{ id: 'CVE-1', severity: 'CRITICAL', package: 'a', version: '1', fixed: ['2', 3] }, { nope: 1 }, 'x', { id: 'CVE-2', severity: 'Medium' }]),
    ).toEqual([
      { id: 'CVE-1', severity: 'critical', package: 'a', version: '1', fixed: ['2'] },
      { id: 'CVE-2', severity: 'moderate', package: '?', version: '?', fixed: [] },
    ]);
    expect(normalizeGrypeDetails({ a: 1 })).toEqual([]);
  });
});
