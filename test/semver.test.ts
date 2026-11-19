import { describe, expect, it } from 'vitest';
import { compareVersions, isPrerelease, parseVersion } from '../src/semver';

describe('semver', () => {
  it('orders npm versions per SemVer 2.0.0 §11', () => {
    const asc = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0', '1.0.1', '1.10.0'];
    for (let i = 0; i < asc.length - 1; i++) {
      expect(compareVersions(asc[i], asc[i + 1], 'npm')).toBeLessThan(0);
      expect(compareVersions(asc[i + 1], asc[i], 'npm')).toBeGreaterThan(0);
    }
  });
  it('ignores build metadata', () => {
    expect(compareVersions('1.0.0+build', '1.0.0', 'npm')).toBe(0);
  });
  it('go: +incompatible ignored for ordering', () => {
    expect(compareVersions('v2.0.0+incompatible', 'v1.9.9', 'go')).toBeGreaterThan(0);
    expect(compareVersions('v2.0.0+incompatible', 'v2.0.0', 'go')).toBe(0);
  });
  it('go pseudo-versions are prereleases', () => {
    expect(isPrerelease('v0.0.0-20240101000000-abcdef123456', 'go')).toBe(true);
    expect(isPrerelease('v1.2.4-0.20240101000000-abcdef123456', 'go')).toBe(true);
    expect(isPrerelease('v1.2.3', 'go')).toBe(false);
    expect(isPrerelease('1.0.0-rc.1', 'npm')).toBe(true);
    expect(isPrerelease('1.0.0', 'npm')).toBe(false);
  });
  it('rejects unparseable', () => {
    expect(parseVersion('latest', 'npm')).toBeNull();
    expect(parseVersion('1.0.0', 'go')).toBeNull();
    expect(compareVersions('latest', '0.0.1', 'npm')).toBeLessThan(0);
  });
});
