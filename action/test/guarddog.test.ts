import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { buildOptions } from '../build.mjs';
import {
  actionDir,
  GUARDDOG_VERSION,
  installGuardDog,
  parseGuardDogJson,
  pythonInterpreter,
  requirementsPath,
  scanGo,
  scanNpm,
  supportedPythons,
} from '../src/guarddog';
import { fakeExec } from './fakes';

const clean = { package: '/t/0.tgz', results: { 'threat-npm-preinstall-script': {}, 'capability-network-outbound': [] }, errors: {}, issues: 0, risks: [] };

const REQ = '# decant-python: 3.12 3.13\nguarddog==3.2.0 \\\n    --hash=sha256:00\n';
const readReq = (text = REQ) => async (p: string) => {
  if (p !== '/act/guarddog-requirements.txt') throw new Error(`ENOENT: ${p}`);
  return text;
};
const VERSION_ARGS = ['-c', 'import sys; print("%d.%d" % sys.version_info[:2])'];
const pyIs = (v: string) => fakeExec((c) => (c.args[0] === '-c' ? { stdout: `${v}\n` } : {}));

describe('pythonInterpreter', () => {
  it('prefers DECANT_PYTHON, then setup-python\'s pythonLocation, then python3', () => {
    expect(pythonInterpreter({ DECANT_PYTHON: '/opt/py', pythonLocation: '/hosted/Python/3.12.9/x64' })).toBe('/opt/py');
    expect(pythonInterpreter({ pythonLocation: '/hosted/Python/3.12.9/x64/' })).toBe('/hosted/Python/3.12.9/x64/bin/python');
    expect(pythonInterpreter({})).toBe('python3');
  });
});

describe('supportedPythons', () => {
  it('reads the decant-python header; a file without one throws', () => {
    expect(supportedPythons(REQ)).toEqual(['3.12', '3.13']);
    expect(() => supportedPythons('guarddog==3.2.0\n')).toThrow(/decant-python/);
  });

  it('the shipped requirements declare their Python versions', () => {
    const req = readFileSync(requirementsPath(actionDir(undefined)), 'utf8');
    expect(supportedPythons(req)).toEqual(['3.12', '3.13']);
  });
});

describe('installGuardDog', () => {
  it('checks the interpreter version, then installs with that interpreter', async () => {
    const exec = pyIs('3.13');
    await installGuardDog(exec, readReq(), '/rt/g', '/act', { pythonLocation: '/hosted/py' });
    expect(exec.calls.map((c) => [c.cmd, ...c.args]).slice(0, 2)).toEqual([
      ['/hosted/py/bin/python', ...VERSION_ARGS],
      ['/hosted/py/bin/python', '-m', 'venv', '/rt/g'],
    ]);
    expect(exec.calls[2]!.cmd).toBe('/rt/g/bin/pip');
  });

  it('a Python the requirements were not compiled for fails clearly before pip runs', async () => {
    const exec = pyIs('3.14');
    await expect(installGuardDog(exec, readReq(), '/rt/g', '/act', {})).rejects.toThrow(
      "GuardDog's pinned dependencies are built for Python 3.12 or 3.13, but python3 is 3.14; add actions/setup-python with python-version: '3.12' before the decant scan step (see docs/adopt.md)",
    );
    expect(exec.calls.map((c) => [c.cmd, ...c.args])).toEqual([['python3', ...VERSION_ARGS]]);
  });

  it('a missing interpreter or header fails before pip runs', async () => {
    const missing = fakeExec(() => ({ code: 127, stderr: 'spawn python3 ENOENT' }));
    await expect(installGuardDog(missing, readReq(), '/rt/g', '/act', {})).rejects.toThrow(/python3 failed to run: spawn python3 ENOENT/);
    const exec = pyIs('3.12');
    await expect(installGuardDog(exec, readReq('guarddog==3.2.0\n'), '/rt/g', '/act', {})).rejects.toThrow(/decant-python/);
    expect(exec.calls).toEqual([]);
  });

  it('creates a venv and installs the hashed requirements from the action path', async () => {
    const exec = pyIs('3.12');
    const gd = await installGuardDog(exec, readReq(), '/rt/decant-guarddog', '/act', {});
    expect(exec.calls.map((c) => [c.cmd, ...c.args])).toEqual([
      ['python3', ...VERSION_ARGS],
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

  // GitHub sets GITHUB_ACTION_PATH only for composite actions; decant runs as a node action.
  it('locates the action directory from the bundle when GITHUB_ACTION_PATH is unset', () => {
    const bundle = new URL('../dist/index.js', import.meta.url).href;
    expect(existsSync(fileURLToPath(bundle))).toBe(true);
    const req = requirementsPath(actionDir(undefined, bundle));
    expect(req).toMatch(/\/action\/guarddog-requirements\.txt$/);
    expect(existsSync(req)).toBe(true);
    // Unbundled (this module's own location) resolves to the same file.
    expect(requirementsPath(actionDir(undefined))).toBe(req);
  });

  it('prefers GITHUB_ACTION_PATH when set', () => {
    expect(requirementsPath(actionDir('/act/'))).toBe('/act/guarddog-requirements.txt');
  });

  it('the built bundle resolves its directory from its own URL', async () => {
    const r = await build({ ...buildOptions, write: false });
    const js = new TextDecoder().decode(r.outputFiles[0]!.contents);
    // ESM output keeps import.meta.url (a CJS bundle would turn it into undefined).
    expect(js).toMatch(/function actionDir\(override, moduleUrl = import\.meta\.url\)/);
    expect(js).toContain('new URL("..", moduleUrl)');
    expect(js).not.toMatch(/GITHUB_ACTION_PATH is not set/);
  });

  it('throws when pip fails', async () => {
    const exec = fakeExec((c) => (c.cmd.endsWith('/pip') ? { code: 1, stderr: 'hash mismatch' } : c.args[0] === '-c' ? { stdout: '3.12' } : {}));
    await expect(installGuardDog(exec, readReq(), '/rt/g', '/act', {})).rejects.toThrow(/pip install.*hash mismatch/);
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
