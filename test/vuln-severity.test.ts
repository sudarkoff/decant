import { describe, expect, it } from 'vitest';
import { cvss31BaseScore, severityOf } from '../src/vuln-severity';

describe('cvss31BaseScore', () => {
  it('scores known vectors', () => {
    expect(cvss31BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
    expect(cvss31BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
    expect(cvss31BaseScore('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')).toBe(1.8);
  });
});

describe('severityOf', () => {
  const v = (score: string) => ({ type: 'CVSS_V3', score });
  it('prefers GHSA database_specific.severity over CVSS', () => {
    expect(severityOf({ database_specific: { severity: 'HIGH' }, severity: [v('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')] })).toBe('high');
    expect(severityOf({ database_specific: { severity: 'moderate' } })).toBe('moderate');
  });
  it('falls back to the max CVSS v3 score, then unknown', () => {
    expect(severityOf({ severity: [v('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'), v('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')] })).toBe('critical');
    expect(severityOf({ database_specific: { severity: 'weird' } })).toBe('unknown');
    expect(severityOf({})).toBe('unknown');
  });
});
