import { describe, expect, it } from 'vitest';
import { GUARDDOG_VERSION, installGuardDog, parseGuardDogJson, scanGo, scanNpm } from '../src/guarddog';
import { fakeExec } from './fakes';

const clean = { package: '/t/0.tgz', results: { 'threat-npm-preinstall-script': {}, 'capability-network-outbound': [] }, errors: {}, issues: 0, risks: [] };

describe('installGuardDog', () => {
  it('creates a venv and installs the hashed requirements from the action path', async () => {
    const exec = fakeExec();
    const gd = await installGuardDog(exec, '/rt/decant-guarddog', '/act');
    expect(exec.calls.map((c) => [c.cmd, ...c.args])).toEqual([
      ['python3', '-m', 'venv', '/rt/decant-guarddog'],
      [
        '/rt/decant-guarddog/bin/pip',
        'install',
        '--disable-pip-version-check',
        '--require-hashes',
        '--no-deps',
        '--only-binary',
        ':all:',
        '-r',
        '/act/guarddog-requirements.txt',
      ],
    ]);
    expect(gd.bin).toBe('/rt/decant-guarddog/bin/guarddog');
    expect(GUARDDOG_VERSION).toBe('3.2.0');
  });

  it('throws when pip fails', async () => {
    const exec = fakeExec((c) => (c.cmd.endsWith('/pip') ? { code: 1, stderr: 'hash mismatch' } : {}));
    await expect(installGuardDog(exec, '/rt/g', '/act')).rejects.toThrow(/pip install.*hash mismatch/);
  });
});

describe('scanNpm / scanGo', () => {
  it('runs guarddog <eco> scan <path> --output-format json with the sandbox on', async () => {
    const exec = fakeExec(() => ({ stdout: JSON.stringify(clean) }));
    expect(await scanNpm(exec, '/g/bin/guarddog', '/t/0.tgz')).toEqual({ result: 'clean', details: [] });
    expect(await scanGo(exec, '/g/bin/guarddog', '/t/1.zip')).toEqual({ result: 'clean', details: [] });
    expect(exec.calls.map((c) => [c.cmd, ...c.args])).toEqual([
      ['/g/bin/guarddog', 'npm', 'scan', '/t/0.tgz', '--output-format', 'json', '--sandbox'],
      ['/g/bin/guarddog', 'go', 'scan', '/t/1.zip', '--output-format', 'json', '--sandbox'],
    ]);
  });

  it('throws on a non-zero exit, invalid JSON, or reported errors (fails closed)', async () => {
    await expect(scanNpm(fakeExec(() => ({ code: 1, stderr: 'sandbox unavailable' })), 'g', '/t/0.tgz')).rejects.toThrow(/sandbox unavailable/);
    await expect(scanNpm(fakeExec(() => ({ stdout: 'nope' })), 'g', '/t/0.tgz')).rejects.toThrow(/invalid JSON/);
    const errs = { ...clean, errors: { 'download-package': 'boom' } };
    await expect(scanNpm(fakeExec(() => ({ stdout: JSON.stringify(errs) })), 'g', '/t/0.tgz')).rejects.toThrow(/download-package/);
    const noResults = { package: 'x', issues: 0, errors: {} };
    await expect(scanNpm(fakeExec(() => ({ stdout: JSON.stringify(noResults) })), 'g', '/t/0.tgz')).rejects.toThrow(/no results/);
  });
});

describe('parseGuardDogJson', () => {
  it('flags any non-capability rule with findings', () => {
    const r = parseGuardDogJson(
      JSON.stringify({
        ...clean,
        results: {
          'threat-npm-preinstall-script': [{ location: 'package/package.json:3', message: 'x' }],
          typosquatting: 'looks like lodash',
          'capability-network-outbound': [{ location: 'a.js:1' }],
          'threat-process-hooks': {},
        },
      }),
    );
    expect(r).toEqual({ result: 'flagged', details: ['threat-npm-preinstall-script (1)', 'typosquatting'] });
  });

  it('capability-only findings are clean (informational in guarddog 3.x)', () => {
    const r = parseGuardDogJson(JSON.stringify({ ...clean, results: { 'capability-process-spawn': [{ location: 'a.js:1' }] } }));
    expect(r.result).toBe('clean');
  });

  it('a correlated risk is flagged', () => {
    const r = parseGuardDogJson(JSON.stringify({ ...clean, risks: [{ x: 1 }], risk_score: { label: 'suspicious' } }));
    expect(r).toEqual({ result: 'flagged', details: ['risk: suspicious'] });
  });
});
