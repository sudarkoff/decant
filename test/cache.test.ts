import { describe, expect, it } from 'vitest';
import { TtlCache } from '../src/cache';
import { errReason } from '../src/index';

describe('TtlCache', () => {
  it('expires an entry at its TTL', () => {
    const c = new TtlCache<number>(10);
    c.set('k', 1, 1_000, 30_000);
    expect(c.get('k', 30_999)).toBe(1);
    expect(c.get('k', 31_000)).toBeUndefined();
    expect(c.get('k', 1_000)).toBeUndefined(); // gone, not resurrected
  });

  it('treats a clock that reads earlier than the write as expired', () => {
    const c = new TtlCache<number>(10);
    c.set('k', 1, 10_000, 30_000);
    expect(c.get('k', 9_999)).toBeUndefined();
  });

  it('evicts the oldest entry past its size cap', () => {
    const c = new TtlCache<number>(2);
    c.set('a', 1, 0, 1_000);
    c.set('b', 2, 0, 1_000);
    c.set('c', 3, 0, 1_000);
    expect([c.get('a', 1), c.get('b', 1), c.get('c', 1)]).toEqual([undefined, 2, 3]);
  });
});

describe('errReason', () => {
  it('names the error and its message on one line, masking token-shaped strings', () => {
    const e = new Error(`D1_ERROR: D1 DB is overloaded.\n Requests queued for too long. dk_read_abc-DEF_123 ${'a1'.repeat(32)}`);
    expect(errReason(e)).toBe('Error: D1_ERROR: D1 DB is overloaded. Requests queued for too long. dk_*** <hex>');
  });

  it('caps the length', () => {
    expect(errReason(new TypeError('x'.repeat(500))).length).toBeLessThanOrEqual(201);
    expect(errReason('nope')).toBe('string');
  });
});
