import { describe, expect, it } from 'vitest';
import { DASHBOARD_HTML, dashboardPage } from '../src/dashboard/page';

const CSP =
  "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'";

describe('dashboard page', () => {
  it('is served as no-store text/html with the exact CSP', async () => {
    const res = dashboardPage();
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('content-security-policy')).toBe(CSP);
    expect(await res.text()).toBe(DASHBOARD_HTML);
  });

  it('makes no external requests', () => {
    expect(DASHBOARD_HTML).not.toMatch(/https?:\/\//);
    expect(DASHBOARD_HTML).not.toMatch(/<script[^>]*\ssrc/i);
    expect(DASHBOARD_HTML).not.toMatch(/<link\b/i);
    expect(DASHBOARD_HTML).not.toMatch(/@import|\burl\(/i);
  });

  it('contains every section heading', () => {
    for (const h of ['Needs attention', 'Activity', 'Security', 'Freshness', 'Uptime', 'Policy', 'Packages', 'Recently resolved']) {
      expect(DASHBOARD_HTML).toMatch(new RegExp(`<h2[^>]*>${h}`));
    }
    expect(DASHBOARD_HTML).toMatch(/<h1[^>]*>decant<\/h1>/);
  });

  it('words uptime as stale serves or failures and hides wide columns on phones', () => {
    expect(DASHBOARD_HTML).toContain('days with stale serves or failures');
    expect(DASHBOARD_HTML).not.toContain('upstream was slow or down');
    expect(DASHBOARD_HTML).toMatch(/max-width: 479px[^}]*\.col-project, \.col-published \{ display: none/);
  });

  it('never parses data as HTML', () => {
    expect(DASHBOARD_HTML).not.toContain('innerHTML');
    expect(DASHBOARD_HTML).not.toContain('outerHTML');
    expect(DASHBOARD_HTML).not.toContain('insertAdjacentHTML');
    expect(DASHBOARD_HTML).not.toContain('document.write');
  });

  it('has labelled, accessible controls and a dark palette', () => {
    expect(DASHBOARD_HTML).toMatch(/<label[^>]*for="project"/);
    expect(DASHBOARD_HTML).toMatch(/<label[^>]*for="q"/);
    for (const r of ['7', '30', '90']) expect(DASHBOARD_HTML).toMatch(new RegExp(`<button[^>]*data-range="${r}"[^>]*aria-pressed`));
    expect(DASHBOARD_HTML).toContain('prefers-color-scheme: dark');
  });
});

// Runs the page's renderFreshness against a minimal fake DOM whose nodes refuse any HTML-parsing setter.
type Node = { tag: string; cls: string | null; textContent: string; children: Node[]; open?: boolean; appendChild(n: Node): Node };
function renderFreshness(data: unknown): Node {
  const m = /\n  function renderFreshness\(f\) \{[\s\S]*?\n  \}\n/.exec(DASHBOARD_HTML);
  if (!m) throw new Error('renderFreshness not found');
  const node = (tag: string, cls: string | null, text?: unknown): Node => {
    const n = {
      tag,
      cls,
      textContent: text === undefined || text === null ? '' : String(text),
      children: [] as Node[],
      appendChild(c: Node) {
        n.children.push(c);
        return c;
      },
    };
    return new Proxy(n, {
      set(t, k, v) {
        if (k === 'innerHTML' || k === 'outerHTML') throw new Error(`${String(k)} used`);
        (t as Record<string | symbol, unknown>)[k] = v;
        return true;
      },
    }) as Node;
  };
  const box = node('div', null);
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  const line = (p: Node, text: string, cls?: string | null) => p.appendChild(node('p', cls ?? null, text));
  const fn = new Function('$', 'el', 'line', 'plural', `${m[0]}; return renderFreshness;`)(() => box, node, line, plural);
  fn(data);
  return box;
}
const texts = (n: Node): string[] => [n.textContent, ...n.children.flatMap(texts)].filter((t) => t !== '');
const find = (n: Node, tag: string): Node | undefined => (n.tag === tag ? n : n.children.map((c) => find(c, tag)).find(Boolean));

describe('dashboard page: freshness', () => {
  const base = { medianAgeDays: 12, minorAvailable: 3 };
  it('lists direct deps, collapses transitive under details with who holds them back', () => {
    const box = renderFreshness({
      ...base,
      majorBehind: {
        direct: [{ project: 'p', package: 'npm:react', version: '17.0.0', latest: '19.0.0', classified: true }],
        transitive: [
          { project: 'p', package: 'npm:glob', version: '7.2.0', latest: '11.0.0', via: ['jest', 'rimraf'] },
          { project: 'p', package: 'go:example.com/m', version: 'v1.0.0', latest: 'v3.0.0', via: [] },
        ],
      },
      transitiveMajorBehindCount: 2,
    });
    const t = texts(box);
    expect(t).toContain('1 direct dependency a major version behind');
    expect(t).toContain('p · npm:react 17.0.0 → 19.0.0');
    const details = find(box, 'details');
    expect(details).toBeDefined();
    expect(details!.open).not.toBe(true);
    expect(texts(details!)).toEqual([
      '2 transitive (held back by their parents)',
      'p · npm:glob 7.2.0 → 11.0.0 · via jest, rimraf',
      'p · go:example.com/m v1.0.0 → v3.0.0',
    ]);
    expect(t.join('\n')).not.toContain('Sync policy from the default branch');
  });

  it('unclassified: a muted note and no transitive section', () => {
    const box = renderFreshness({
      ...base,
      majorBehind: { direct: [{ project: 'p', package: 'npm:a', version: '1.0.0', latest: '2.0.0', classified: false }], transitive: [] },
      transitiveMajorBehindCount: 0,
    });
    const note = box.children.find((c) => c.textContent === 'Sync policy from the default branch to classify direct vs transitive.');
    expect(note?.cls).toBe('muted');
    expect(find(box, 'details')).toBeUndefined();
  });

  it('nothing behind: zero line, no list, no details', () => {
    const box = renderFreshness({ ...base, majorBehind: { direct: [], transitive: [] }, transitiveMajorBehindCount: 0 });
    expect(texts(box)).toContain('0 direct dependencies a major version behind');
    expect(find(box, 'ul')).toBeUndefined();
    expect(find(box, 'details')).toBeUndefined();
  });

  it('builds the freshness section with text nodes only', () => {
    const m = /function renderFreshness\(f\) \{[\s\S]*?\n  \}\n/.exec(DASHBOARD_HTML)![0];
    expect(m).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  });
});
