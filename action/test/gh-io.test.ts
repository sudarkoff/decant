import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendSummary, error, exportVar, getInput, mask, notice, setOutput, warning } from '../src/gh-io';

function capture() {
  const out: string[] = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(((s: string) => {
    out.push(String(s));
    return true;
  }) as typeof process.stdout.write);
  return out;
}
afterEach(() => vi.restoreAllMocks());

describe('getInput', () => {
  it('reads INPUT_<NAME> trimmed with - to _', () => {
    expect(getInput('policy-path', { INPUT_POLICY_PATH: ' x ' })).toBe('x');
  });
  it('returns empty string when unset', () => {
    expect(getInput('nope', {})).toBe('');
  });
});

describe('commands', () => {
  it('error escapes newlines', () => {
    const out = capture();
    error('a\nb');
    expect(out.join('')).toBe('::error::a%0Ab\n');
  });
  it('escapes % and \\r', () => {
    const out = capture();
    warning('100%\r');
    expect(out.join('')).toBe('::warning::100%25%0D\n');
  });
  it('notice with file', () => {
    const out = capture();
    notice('hi', 'a/b.json');
    expect(out.join('')).toBe('::notice file=a/b.json::hi\n');
  });
  it('mask', () => {
    const out = capture();
    mask('s3cret');
    expect(out.join('')).toBe('::add-mask::s3cret\n');
  });
});

describe('file commands', () => {
  function tmp(name: string) {
    const p = join(mkdtempSync(join(tmpdir(), 'gh-io-')), name);
    writeFileSync(p, '');
    return p;
  }
  it('setOutput uses the multiline-safe form', () => {
    const f = tmp('out');
    setOutput('a', 'b', { GITHUB_OUTPUT: f });
    expect(readFileSync(f, 'utf8')).toMatch(/^a<<\S+\nb\n\S+\n$/);
  });
  it('appendSummary appends markdown', () => {
    const f = tmp('sum');
    appendSummary('# hi', { GITHUB_STEP_SUMMARY: f });
    expect(readFileSync(f, 'utf8')).toBe('# hi\n');
  });
  it('exportVar uses name<<delim form, multiline safe', () => {
    const f = tmp('env');
    exportVar('K', 'l1\nl2', { GITHUB_ENV: f });
    const t = readFileSync(f, 'utf8');
    const m = /^K<<(\S+)\nl1\nl2\n(\S+)\n$/.exec(t);
    expect(m).not.toBeNull();
    expect(m![1]).toBe(m![2]);
  });
  it('is a no-op without the env file', () => {
    expect(() => setOutput('a', 'b', {})).not.toThrow();
  });
});
