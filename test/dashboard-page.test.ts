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

// Runs the page's Needs-attention renderer against a minimal fake DOM.
type ANode = { tag: string; className: string | null; textContent: string; children: ANode[]; href?: string; target?: string; rel?: string; appendChild(n: ANode): ANode; firstChild: ANode | null };
function renderAttention(data: unknown): { box: ANode; resolved: ANode } {
  const m = /\n  \/\/ ---- Needs attention \/ Recently resolved ----\n[\s\S]*?\n  \/\/ ---- Activity ----\n/.exec(DASHBOARD_HTML);
  if (!m) throw new Error('attention block not found');
  const node = (tag: string, cls?: string | null, text?: unknown): ANode => {
    const n: ANode = {
      tag,
      className: cls ?? null,
      textContent: text === undefined || text === null ? '' : String(text),
      children: [],
      appendChild(c: ANode) {
        n.children.push(c);
        return c;
      },
      get firstChild() {
        return n.children[0] ?? null;
      },
    };
    return new Proxy(n, {
      set(t, k, v) {
        if (k === 'innerHTML' || k === 'outerHTML') throw new Error(`${String(k)} used`);
        (t as unknown as Record<string | symbol, unknown>)[k] = v;
        return true;
      },
    });
  };
  const nodes: Record<string, ANode> = { attention: node('div'), resolved: node('div'), 'attention-count': node('span') };
  const doc = { createTextNode: (t: string) => node('#text', null, t) };
  const line = (p: ANode, text: string, cls?: string | null) => p.appendChild(node('p', cls ?? null, text));
  const fn = new Function('$', 'el', 'line', 'shortDate', 'document', 'window', `${m[0]}; return renderAttention;`)(
    (id: string) => nodes[id],
    node,
    line,
    (iso: string) => iso.slice(0, 10),
    doc,
    { URL },
  );
  fn(data);
  return { box: nodes.attention!, resolved: nodes.resolved! };
}
const all = (n: ANode): ANode[] => [n, ...n.children.flatMap(all)];

describe('dashboard page: needs attention', () => {
  const base = { key: 'k', project: 'web', title: 'undici@7.29.0 has GHSA-x', detail: 'high: leak', firstSeen: '2026-11-18T00:00:00Z' };

  it('renders the to-do (backtick parts as code) and allowlisted links only', () => {
    const { box } = renderAttention({
      open: [
        {
          ...base,
          kind: 'vuln',
          todo: 'Fixed in `7.29.1`. Merge it.',
          links: [
            { label: 'Open security PRs', url: 'https://github.com/acme/web/pulls?q=is%3Apr' },
            { label: 'Advisory', url: 'https://osv.dev/vulnerability/GHSA-x' },
            { label: 'npm', url: 'https://www.npmjs.com/package/a/v/1.0.0' },
            { label: 'go', url: 'https://pkg.go.dev/example.com/m@v1.0.0' },
            { label: 'js', url: 'javascript:alert(1)' },
            { label: 'http', url: 'http://osv.dev/x' },
            { label: 'evil', url: 'https://github.com.evil.example/x' },
            { label: 'creds', url: 'https://user:pw@github.com/x' },
            { label: 'port', url: 'https://github.com:8443/x' },
            { label: 'data', url: 'data:text/html,hi' },
            { label: 'junk', url: 'not a url' },
          ],
        },
      ],
      resolved: [],
    });
    const nodes = all(box);
    const todo = nodes.find((n) => n.className === 'todo')!;
    expect(todo.children.map((c) => [c.tag, c.textContent])).toEqual([
      ['span', 'What to do'],
      ['#text', 'Fixed in '],
      ['code', '7.29.1'],
      ['#text', '. Merge it.'],
    ]);
    const links = nodes.filter((n) => n.tag === 'a');
    expect(links.map((a) => a.textContent)).toEqual(['Open security PRs', 'Advisory', 'npm', 'go']);
    for (const a of links) {
      expect(a.target).toBe('_blank');
      expect(a.rel).toBe('noopener noreferrer');
    }
    expect(links[0]!.href).toBe('https://github.com/acme/web/pulls?q=is%3Apr');
  });

  it('labels kinds, lists findings, and calls an archive anomaly "Not scanned"', () => {
    const { box } = renderAttention({
      open: [
        { ...base, kind: 'flagged', todo: 't', links: [], findings: [{ rule: 'npm-install-script', note: 'postinstall at package.json:12' }] },
        { ...base, kind: 'flagged', todo: 't', links: [], findings: [{ rule: 'archive-anomaly', note: 'bad zip' }] },
        { ...base, kind: 'conflict', project: null, todo: 't', links: [] },
        { ...base, kind: 'silent', todo: 't', links: [] },
      ],
      resolved: [],
    });
    const labels = all(box).filter((n) => (n.className ?? '').startsWith('label ')).map((n) => [n.textContent, n.className]);
    expect(labels).toEqual([
      ['Flagged', 'label warn'],
      ['Not scanned', 'label warn'],
      ['Changed', 'label danger'],
      ['Quiet', 'label info'],
    ]);
    const rule = all(box).find((n) => n.className === 'rules')!.children[0]!;
    expect(rule.children.map((c) => [c.tag, c.textContent])).toEqual([
      ['code', 'npm-install-script'],
      ['#text', ' postinstall at package.json:12'],
    ]);
  });

  it('prefixes the project only when the title does not already name it, and never prefixes project-less items', () => {
    const { box, resolved } = renderAttention({
      open: [
        { ...base, kind: 'vuln' },
        { ...base, kind: 'silent', project: 'docs-site', title: 'docs-site has had no requests in 14 days' },
        { ...base, kind: 'conflict', project: null, title: 'tinyrainbow@3.2.0 was republished upstream' },
      ],
      resolved: [{ ...base, kind: 'conflict', project: null, title: 'c@1.0.0 was republished upstream', resolvedAt: '2026-11-19T00:00:00Z' }],
    });
    expect(all(box).filter((n) => n.className === 'title').map((n) => n.textContent)).toEqual([
      'web · undici@7.29.0 has GHSA-x',
      'docs-site has had no requests in 14 days',
      'tinyrainbow@3.2.0 was republished upstream',
    ]);
    expect(all(resolved).map((n) => n.textContent)).toContain('c@1.0.0 was republished upstream');
  });

  it('items without a to-do or links (older Worker) render as before', () => {
    const { box } = renderAttention({ open: [{ ...base, kind: 'blocked' }], resolved: [] });
    expect(all(box).some((n) => n.className === 'todo' || n.className === 'links')).toBe(false);
  });

  it('builds the section with text nodes only', () => {
    const m = /\/\/ ---- Needs attention[\s\S]*?\/\/ ---- Activity/.exec(DASHBOARD_HTML)![0];
    expect(m).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|setAttribute\('href'/);
  });
});
