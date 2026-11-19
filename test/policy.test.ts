import { describe, expect, it } from 'vitest';
import { parsePolicy } from '../src/policy/schema';
import { decide } from '../src/policy/decide';
import schema from '../schema/policy.json';

describe('parsePolicy', () => {
  it('applies defaults to a minimal policy', () => {
    const r = parsePolicy({ project: 't' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.policy.cooldownDays).toBe(7);
    expect(r.policy.autoShip).toEqual({ critical: 'auto', high: 'auto', moderate: 'approve', low: 'approve' });
    expect(r.policy.allow).toEqual([]);
    expect(r.policy.block).toEqual([]);
  });
  it('rejects bad cooldownDays', () => {
    for (const v of [-1, 366, 1.5, '7']) {
      const r = parsePolicy({ project: 't', cooldownDays: v });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.errors.join()).toContain('cooldownDays');
    }
  });
  it('rejects unknown top-level keys but allows $schema', () => {
    expect(parsePolicy({ project: 't', foo: 1 }).ok).toBe(false);
    expect(parsePolicy({ project: 't', $schema: 'x' }).ok).toBe(true);
  });
  it('rejects a bad advisory', () => {
    const r = parsePolicy({ project: 't', block: [{ package: 'npm:a@1.0.0', reason: 'r', advisory: 'GHSA-1' }] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join()).toContain('advisory');
  });
  it('accepts valid advisories and entries', () => {
    const r = parsePolicy({
      project: 't',
      allow: [{ package: 'npm:@s/n@1.2.3', reason: 'r', advisory: 'GHSA-abcd-1234-wxyz', added: '2026-11-19' }],
      block: [{ package: 'go:github.com/x/y@v1.0.0', reason: 'r', advisory: 'CVE-2026-12345' }],
    });
    expect(r.ok).toBe(true);
  });
  it('rejects bad package ids and dates', () => {
    expect(parsePolicy({ project: 't', block: [{ package: 'nope', reason: 'r' }] }).ok).toBe(false);
    for (const added of ['2026-02-30', '2026-1-1', 'x']) {
      expect(parsePolicy({ project: 't', allow: [{ package: 'npm:a@1.0.0', reason: 'r', added }] }).ok).toBe(false);
    }
  });
  it('merges partial autoShip and rejects bad values', () => {
    const r = parsePolicy({ project: 't', autoShip: { moderate: 'auto' } });
    expect(r.ok && r.policy.autoShip).toEqual({ critical: 'auto', high: 'auto', moderate: 'auto', low: 'approve' });
    expect(parsePolicy({ project: 't', autoShip: { urgent: 'auto' } }).ok).toBe(false);
    expect(parsePolicy({ project: 't', autoShip: { low: 'yes' } }).ok).toBe(false);
  });
  it('requires project and an object', () => {
    expect(parsePolicy({}).ok).toBe(false);
    expect(parsePolicy(null).ok).toBe(false);
  });
  it('schema file lists the same top-level properties', () => {
    expect(Object.keys(schema.properties).sort()).toEqual(['$schema', 'allow', 'autoShip', 'block', 'cooldownDays', 'project']);
  });
});

describe('decide', () => {
  const now = new Date('2026-11-19T00:00:00Z');
  const base = { publishTime: null as Date | null, conflict: false, blocked: false, allowed: false, cooldownDays: 7, now };
  it('allows at exactly 7 days', () => {
    expect(decide({ ...base, publishTime: new Date('2026-11-12T00:00:00Z') })).toBe('allow');
  });
  it('hides one second short', () => {
    expect(decide({ ...base, publishTime: new Date('2026-11-12T00:00:01Z') })).toBe('hidden');
  });
  it('hides unknown publish time unless allowed', () => {
    expect(decide(base)).toBe('hidden');
    expect(decide({ ...base, allowed: true })).toBe('allow');
  });
  it('blocked beats allowed; conflict blocks', () => {
    expect(decide({ ...base, blocked: true, allowed: true })).toBe('blocked');
    expect(decide({ ...base, conflict: true, allowed: true })).toBe('blocked');
  });
  it('cooldown 0 allows a version published now', () => {
    expect(decide({ ...base, cooldownDays: 0, publishTime: now })).toBe('allow');
  });
});
