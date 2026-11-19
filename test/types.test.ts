import { describe, expect, it } from 'vitest';
import { formatPackageId, parsePackageId } from '../src/types';

describe('package ids', () => {
  it('parses scoped npm', () => {
    expect(parsePackageId('npm:@a/b@1.0.0')).toEqual({ eco: 'npm', name: '@a/b', version: '1.0.0' });
  });
  it('parses go', () => {
    expect(parsePackageId('go:github.com/x/y@v1.2.3')).toEqual({ eco: 'go', name: 'github.com/x/y', version: 'v1.2.3' });
  });
  it('rejects unknown ecosystems', () => {
    expect(parsePackageId('pypi:x@1')).toBeNull();
  });
  it('round-trips', () => {
    for (const id of ['npm:@a/b@1.0.0', 'npm:left-pad@1.3.0', 'go:github.com/x/y@v1.2.3']) {
      expect(formatPackageId(parsePackageId(id)!)).toBe(id);
    }
  });
});
