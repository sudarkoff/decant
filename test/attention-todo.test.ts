import { describe, expect, it } from 'vitest';
import { findingsOf, lowestFixed, packageUrl, todoFor } from '../src/dashboard/attention';

const SEC_PRS = 'https://github.com/acme/web-app/pulls?q=is%3Apr+is%3Aopen+label%3Adecant%3Asecurity';
const FAILING_PRS = 'https://github.com/acme/web-app/pulls?q=is%3Apr+is%3Aopen+status%3Afailure';

describe('packageUrl', () => {
  it('npm: plain and scoped names keep their path shape; versions are encoded', () => {
    expect(packageUrl('npm', 'undici', '7.29.0')).toBe('https://www.npmjs.com/package/undici/v/7.29.0');
    expect(packageUrl('npm', '@img/sharp-wasm32', '0.34.1')).toBe('https://www.npmjs.com/package/@img/sharp-wasm32/v/0.34.1');
    expect(packageUrl('npm', 'a', '1.0.0+build.1')).toBe('https://www.npmjs.com/package/a/v/1.0.0%2Bbuild.1');
  });
  it('go: module path case is kept (pkg.go.dev is case-sensitive, not !-escaped)', () => {
    expect(packageUrl('go', 'github.com/BurntSushi/toml', 'v1.4.0')).toBe('https://pkg.go.dev/github.com/BurntSushi/toml@v1.4.0');
    expect(packageUrl('go', 'example.com/m', 'v2.0.0+incompatible')).toBe('https://pkg.go.dev/example.com/m@v2.0.0%2Bincompatible');
  });
  it('encodes anything unusual inside a path segment', () => {
    expect(packageUrl('npm', 'a b?#', '1.0.0')).toBe('https://www.npmjs.com/package/a%20b%3F%23/v/1.0.0');
  });
});

describe('lowestFixed', () => {
  it('picks the lowest fixed version above the installed one', () => {
    expect(lowestFixed(['7.29.1', '6.21.3', '8.0.0'], '7.29.0', 'npm')).toBe('7.29.1');
    expect(lowestFixed(['7.29.1', '6.21.3'], '6.5.0', 'npm')).toBe('6.21.3');
    expect(lowestFixed(['v0.59.0', 'v0.33.0'], 'v0.58.0', 'go')).toBe('v0.59.0');
  });
  it('null when nothing is above, the list is unknown, or a version does not parse', () => {
    expect(lowestFixed(['1.0.0'], '1.0.0', 'npm')).toBeNull();
    expect(lowestFixed(null, '1.0.0', 'npm')).toBeNull();
    expect(lowestFixed([], '1.0.0', 'npm')).toBeNull();
    expect(lowestFixed(['1.2.0'], 'latest', 'npm')).toBeNull();
    expect(lowestFixed(['garbage', '1.2.0'], '1.0.0', 'npm')).toBe('1.2.0');
  });
});

describe('findingsOf', () => {
  it('reads finding objects: rule plus count, message and locations', () => {
    expect(
      findingsOf([
        { rule: 'npm-install-script', message: 'postinstall', locations: ['package/package.json:12'] },
        { rule: 'npm-exec-base64', count: 2, locations: ['package/install.js:88', 'package/x.js:1'] },
      ]),
    ).toEqual([
      { rule: 'npm-install-script', note: 'postinstall at package/package.json:12' },
      { rule: 'npm-exec-base64', note: '2 hits at package/install.js:88, package/x.js:1' },
    ]);
  });
  it('reads the legacy list of rule strings, drops junk, caps the list', () => {
    expect(findingsOf(['shady-links', 7, null, { nope: 1 }])).toEqual([{ rule: 'shady-links', note: '' }]);
    expect(findingsOf({ malicious: ['MAL-1'] })).toEqual([]);
    expect(findingsOf(null)).toEqual([]);
    expect(findingsOf(Array.from({ length: 20 }, (_, i) => `r${i}`))).toHaveLength(6);
  });
  it('clips long text', () => {
    const [f] = findingsOf([{ rule: 'r', message: 'x'.repeat(500) }]);
    expect(f!.note.length).toBeLessThanOrEqual(200);
    expect(f!.note.endsWith('…')).toBe(true);
  });
});

describe('todoFor', () => {
  const pkg = { eco: 'npm', name: 'undici', version: '7.29.0' } as const;

  it('vuln with a fix: merge the security PR; links to the open security PRs and the advisory', () => {
    expect(todoFor({ kind: 'vuln', ...pkg, advisory: 'GHSA-1234-abcd-5678', fixed: '7.29.1', repo: 'acme/web-app' })).toEqual({
      todo: 'Fixed in `7.29.1`. Merge the daily security PR: it includes this fix (security fixes skip the cooldown).',
      links: [
        { label: 'Open security PRs', url: SEC_PRS },
        { label: 'Advisory', url: 'https://osv.dev/vulnerability/GHSA-1234-abcd-5678' },
      ],
    });
  });

  it('vuln with a fix but no known repo: advisory only', () => {
    expect(todoFor({ kind: 'vuln', ...pkg, advisory: 'GHSA-x', fixed: '7.29.1', repo: null }).links).toEqual([
      { label: 'Advisory', url: 'https://osv.dev/vulnerability/GHSA-x' },
    ]);
  });

  it('vuln without a fix: nothing to do now; advisory link only', () => {
    expect(todoFor({ kind: 'vuln', ...pkg, advisory: 'GO-2026-4410', fixed: null, repo: 'acme/web-app' })).toEqual({
      todo: 'No fixed version yet. Nothing to do now: decant re-checks daily and this card updates when a fix ships.',
      links: [{ label: 'Advisory', url: 'https://osv.dev/vulnerability/GO-2026-4410' }],
    });
  });

  it('vuln whose fixed versions are not known yet: points at the advisory, does not claim there is no fix', () => {
    expect(todoFor({ kind: 'vuln', ...pkg, advisory: 'GHSA-x', fixed: null, fixedKnown: false, repo: 'acme/web-app' })).toEqual({
      todo: 'decant has not looked up a fixed version yet (it will within a day). The advisory lists the fixed versions.',
      links: [{ label: 'Advisory', url: 'https://osv.dev/vulnerability/GHSA-x' }],
    });
  });

  it('flagged: review, then label or block; PR list and package page', () => {
    const r = todoFor({ kind: 'flagged', ...pkg, notScanned: false, repo: 'acme/web-app' });
    expect(r.todo).toBe(
      'Read the findings. If they are expected, add the `decant:reviewed` label to the PR; if not, block the version in `decant.json`.',
    );
    expect(r.links).toEqual([
      { label: 'PRs failing checks', url: FAILING_PRS },
      { label: 'View on npm', url: 'https://www.npmjs.com/package/undici/v/7.29.0' },
    ]);
  });

  it('flagged archive anomaly: nothing was scanned; same links; go package page', () => {
    const r = todoFor({ kind: 'flagged', eco: 'go', name: 'github.com/klauspost/compress', version: 'v1.20.2', notScanned: true, repo: null });
    expect(r.todo).toBe(
      'Nothing inside was scanned. Download the module zip and check what makes it unusual (often zip test fixtures). Add `decant:reviewed` only once you have.',
    );
    expect(r.links).toEqual([{ label: 'View on pkg.go.dev', url: 'https://pkg.go.dev/github.com/klauspost/compress@v1.20.2' }]);
  });

  it('flagged npm archive anomaly says tarball, not module zip', () => {
    expect(todoFor({ kind: 'flagged', ...pkg, notScanned: true, repo: null }).todo).toContain('Download the tarball');
  });

  it('malicious: remove and rotate; advisory for the first MAL id, package page', () => {
    expect(todoFor({ kind: 'malicious', eco: 'npm', name: '@evil/color-strng', version: '1.0.4', advisories: ['MAL-2026-2211', 'MAL-2026-2212'] })).toEqual({
      todo: 'Remove it from the lockfile. If a build ever installed it, rotate any secrets that build could read.',
      links: [
        { label: 'Advisory', url: 'https://osv.dev/vulnerability/MAL-2026-2211' },
        { label: 'View on npm', url: 'https://www.npmjs.com/package/@evil/color-strng/v/1.0.4' },
      ],
    });
    expect(todoFor({ kind: 'malicious', ...pkg, advisories: [] }).links.map((l) => l.label)).toEqual(['View on npm']);
  });

  it('blocked, conflict and silent', () => {
    expect(todoFor({ kind: 'blocked', ...pkg })).toEqual({
      todo: 'Blocked by your policy. Remove or replace it, or lift the block in `decant.json`.',
      links: [{ label: 'View on npm', url: 'https://www.npmjs.com/package/undici/v/7.29.0' }],
    });
    expect(todoFor({ kind: 'conflict', ...pkg })).toEqual({
      todo: "decant keeps serving the copy it verified, so builds are unaffected. Check the package's repo for a re-publish notice; if you can't explain it, block the version.",
      links: [{ label: 'View on npm', url: 'https://www.npmjs.com/package/undici/v/7.29.0' }],
    });
    expect(todoFor({ kind: 'silent' })).toEqual({
      todo: 'If the project is still building, its install step is probably bypassing decant. Check the registry setting and that its read token still works.',
      links: [{ label: 'Setup guide', url: 'https://github.com/sudarkoff/decant/blob/main/docs/adopt.md' }],
    });
  });

  it('a repo that is not owner/name never becomes a link', () => {
    for (const repo of ['acme', 'acme/web app', '../x/y', 'acme/web-app/extra', 'a@b/c']) {
      expect(todoFor({ kind: 'vuln', ...pkg, advisory: 'GHSA-x', fixed: '7.29.1', repo }).links.map((l) => l.label)).toEqual(['Advisory']);
    }
  });

  it('encodes advisory ids', () => {
    expect(todoFor({ kind: 'vuln', ...pkg, advisory: 'A/B?c', fixed: null, repo: null }).links[0]!.url).toBe('https://osv.dev/vulnerability/A%2FB%3Fc');
  });
});
