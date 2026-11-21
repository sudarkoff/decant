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
  it('parses docker: fully qualified repository and a sha256 digest', () => {
    const d = `sha256:${'a'.repeat(64)}`;
    expect(parsePackageId(`docker:docker.io/library/node@${d}`)).toEqual({ eco: 'docker', name: 'docker.io/library/node', version: d });
    expect(parsePackageId(`docker:ghcr.io/org/x@${d}`)).toEqual({ eco: 'docker', name: 'ghcr.io/org/x', version: d });
    expect(parsePackageId(`docker:registry.example.com:5000/a/b-c@${d}`)?.name).toBe('registry.example.com:5000/a/b-c');
    expect(formatPackageId(parsePackageId(`docker:docker.io/library/node@${d}`)!)).toBe(`docker:docker.io/library/node@${d}`);
  });
  it('rejects docker ids that are not normalized or not pinned by sha256 digest', () => {
    const d = `sha256:${'a'.repeat(64)}`;
    for (const id of [
      `docker:node@${d}`, // short name: must be docker.io/library/node
      `docker:library/node@${d}`,
      'docker:docker.io/library/node@22',
      `docker:docker.io/library/node@sha256:${'A'.repeat(64)}`,
      `docker:docker.io/library/node@sha256:${'a'.repeat(63)}`,
      `docker:docker.io/library/Node@${d}`,
      `docker:docker.io/library/node:22@${d}`,
      `docker:docker.io/library/../x@${d}`,
      `docker:index.docker.io/library/node@${d}`,
    ]) {
      expect(parsePackageId(id), id).toBeNull();
    }
  });
});
