import { describe, expect, it, vi } from 'vitest';
import { github } from '../src/github';
import { fakeFetch, jsonRes, type FetchCall } from './fakes';

const TOKEN = 'ghs_SECRETSECRET';
const API = 'https://api.github.com';
const R = `${API}/repos/o/r`;
const BOT = { login: 'github-actions[bot]', type: 'Bot' };
const HUMAN = { login: 'mallory', type: 'User' };

function route(table: Record<string, (c: FetchCall) => Response>) {
  return fakeFetch((c) => {
    const h = table[`${c.method} ${c.url}`];
    return h ? h(c) : undefined;
  });
}

describe('github REST basics', () => {
  it('sends the API headers and a timeout', async () => {
    const f = route({ [`GET ${R}`]: () => jsonRes({ default_branch: 'trunk' }) });
    expect(await github(f, TOKEN, 'o/r').defaultBranch()).toBe('trunk');
    const h = f.calls[0]!.headers;
    expect(h.get('accept')).toBe('application/vnd.github+json');
    expect(h.get('x-github-api-version')).toBe('2022-11-28');
    expect(h.get('authorization')).toBe(`Bearer ${TOKEN}`);
    expect(f.calls[0]!.signal).toBeInstanceOf(AbortSignal);
  });

  it('rejects a malformed repo', () => {
    expect(() => github(fakeFetch(() => undefined), TOKEN, 'nope')).toThrow(/owner\/name/);
  });

  it('never puts the token in a thrown error', async () => {
    const f = fakeFetch((c) => new Response(`denied ${c.headers.get('authorization')}`, { status: 403 }));
    const e = await github(f, TOKEN, 'o/r').defaultBranch().catch((x: Error) => x);
    expect(e).toBeInstanceOf(Error);
    expect((e as Error).message).toMatch(/403/);
    expect((e as Error).message).not.toContain(TOKEN);
  });
});

describe('upsertComment', () => {
  it('edits an existing comment containing the marker instead of posting', async () => {
    const f = route({
      [`GET ${R}/issues/5/comments?per_page=100`]: () =>
        jsonRes([
          { id: 1, body: 'hello', user: BOT },
          { id: 2, body: '<!-- decant -->\nold', user: BOT },
        ]),
      [`PATCH ${R}/issues/comments/2`]: () => jsonRes({ id: 2 }),
    });
    expect(await github(f, TOKEN, 'o/r').upsertComment(5, '<!-- decant -->', '<!-- decant -->\nnew')).toEqual({ id: 2, created: false });
    expect(f.calls.map((c) => c.method)).toEqual(['GET', 'PATCH']);
    expect(JSON.parse(f.calls[1]!.body!)).toEqual({ body: '<!-- decant -->\nnew' });
  });

  it('posts when none has the marker, adding the marker if missing', async () => {
    const f = route({
      [`GET ${R}/issues/5/comments?per_page=100`]: () => jsonRes([{ id: 1, body: 'hello' }]),
      [`POST ${R}/issues/5/comments`]: () => jsonRes({ id: 9 }, 201),
    });
    expect(await github(f, TOKEN, 'o/r').upsertComment(5, '<!-- m -->', 'body')).toEqual({ id: 9, created: true });
    expect(JSON.parse(f.calls[1]!.body!).body).toBe('<!-- m -->\nbody');
  });

  it("ignores a human's comment containing the marker and posts a new one", async () => {
    const f = route({
      [`GET ${R}/issues/5/comments?per_page=100`]: () => jsonRes([{ id: 1, body: '<!-- m -->\nfake', user: HUMAN }]),
      [`POST ${R}/issues/5/comments`]: () => jsonRes({ id: 9 }, 201),
    });
    expect(await github(f, TOKEN, 'o/r').upsertComment(5, '<!-- m -->', 'body')).toEqual({ id: 9, created: true });
    expect(f.calls.some((c) => c.method === 'PATCH')).toBe(false);
  });

  it('with selfLogin, matches only that login (not other bots)', async () => {
    const f = route({
      [`GET ${R}/issues/5/comments?per_page=100`]: () =>
        jsonRes([
          { id: 1, body: '<!-- m -->', user: BOT },
          { id: 2, body: '<!-- m -->', user: { login: 'decant-app[bot]', type: 'Bot' } },
        ]),
      [`PATCH ${R}/issues/comments/2`]: () => jsonRes({ id: 2 }),
    });
    const r = await github(f, TOKEN, 'o/r', { selfLogin: 'decant-app[bot]' }).upsertComment(5, '<!-- m -->', 'b');
    expect(r).toEqual({ id: 2, created: false });
  });
});

describe('upsertIssue', () => {
  it('updates the open issue with the exact title (title only, not labels)', async () => {
    const list = `${R}/issues?state=open&per_page=100`;
    const f = route({
      [`GET ${list}&labels=decant%3Asecurity`]: () => jsonRes([]),
      [`GET ${list}`]: () =>
        jsonRes([
          { number: 1, title: 'decant: GHSA-x in a (extra)', user: BOT },
          { number: 2, title: 'decant: GHSA-x in a', pull_request: {}, user: BOT },
        ], 200, { link: `<${list}&page=2>; rel="next"` }),
      [`GET ${list}&page=2`]: () => jsonRes([{ number: 3, title: 'decant: GHSA-x in a', user: BOT, labels: [] }]),
      [`PATCH ${R}/issues/3`]: () => jsonRes({ number: 3 }),
    });
    const r = await github(f, TOKEN, 'o/r').upsertIssue('decant: GHSA-x in a', 'b', ['decant:security']);
    expect(r).toEqual({ number: 3, created: false });
    expect(JSON.parse(f.calls.at(-1)!.body!)).toEqual({ body: 'b' });
  });

  it('creates when no exact title match', async () => {
    const f = route({
      [`GET ${R}/issues?state=open&per_page=100`]: () => jsonRes([{ number: 1, title: 'Other' }]),
      [`POST ${R}/issues`]: () => jsonRes({ number: 7 }, 201),
    });
    expect(await github(f, TOKEN, 'o/r').upsertIssue('T', 'b', [])).toEqual({ number: 7, created: true });
    expect(JSON.parse(f.calls[1]!.body!)).toEqual({ title: 'T', body: 'b', labels: [] });
  });

  it("ignores a human's issue with the exact title and creates a new one", async () => {
    const f = route({
      [`GET ${R}/issues?state=open&per_page=100&labels=decant%3Asecurity`]: () => jsonRes([{ number: 1, title: 'T', user: HUMAN }]),
      [`GET ${R}/issues?state=open&per_page=100`]: () => jsonRes([{ number: 1, title: 'T', user: HUMAN }]),
      [`POST ${R}/issues`]: () => jsonRes({ number: 8 }, 201),
    });
    expect(await github(f, TOKEN, 'o/r').upsertIssue('T', 'b', ['decant:security'])).toEqual({ number: 8, created: true });
  });

  it('with selfLogin, lists only issues created by it', async () => {
    const f = route({
      [`GET ${R}/issues?state=open&per_page=100&creator=decant-app%5Bbot%5D`]: () =>
        jsonRes([{ number: 6, title: 'T', user: { login: 'decant-app[bot]', type: 'Bot' } }]),
      [`PATCH ${R}/issues/6`]: () => jsonRes({ number: 6 }),
    });
    const r = await github(f, TOKEN, 'o/r', { selfLogin: 'decant-app[bot]' }).upsertIssue('T', 'b', ['decant:security']);
    expect(r).toEqual({ number: 6, created: false });
    expect(f.calls.length).toBe(2);
  });

  it('without selfLogin, pre-filters by labels and stops on a hit', async () => {
    const f = route({
      [`GET ${R}/issues?state=open&per_page=100&labels=decant%3Asecurity%2Cdecant%3Ahigh`]: () => jsonRes([{ number: 2, title: 'T', user: BOT }]),
      [`PATCH ${R}/issues/2`]: () => jsonRes({ number: 2 }),
    });
    const r = await github(f, TOKEN, 'o/r').upsertIssue('T', 'b', ['decant:security', 'decant:high']);
    expect(r).toEqual({ number: 2, created: false });
    expect(f.calls.length).toBe(2);
  });

  it('without selfLogin, falls back to the unfiltered list when the label filter finds nothing', async () => {
    const f = route({
      [`GET ${R}/issues?state=open&per_page=100&labels=decant%3Asecurity`]: () => jsonRes([]),
      [`GET ${R}/issues?state=open&per_page=100`]: () => jsonRes([{ number: 4, title: 'T', user: BOT }]),
      [`PATCH ${R}/issues/4`]: () => jsonRes({ number: 4 }),
    });
    expect(await github(f, TOKEN, 'o/r').upsertIssue('T', 'b', ['decant:security'])).toEqual({ number: 4, created: false });
  });

  it('cap hit without a match → creates a new issue (warns), no throw', async () => {
    const warn = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    let n = 0;
    const f = fakeFetch((c) =>
      c.method === 'POST'
        ? jsonRes({ number: 11 }, 201)
        : jsonRes([{ number: 99, title: 'spam', user: HUMAN }], 200, { link: `<${R}/issues?state=open&per_page=100&page=${++n + 1}>; rel="next"` }),
    );
    expect(await github(f, TOKEN, 'o/r').upsertIssue('T', 'b', [])).toEqual({ number: 11, created: true });
    expect(f.calls.filter((c) => c.method === 'GET').length).toBe(10);
    expect(warn.mock.calls.map((a) => String(a[0])).join('')).toMatch(/::warning::.*10 pages/);
    warn.mockRestore();
  });

  it('a match on page 1 stops paging', async () => {
    const f = route({
      [`GET ${R}/issues?state=open&per_page=100`]: () =>
        jsonRes([{ number: 1, title: 'T', user: BOT }], 200, { link: `<${R}/issues?state=open&per_page=100&page=2>; rel="next"` }),
      [`PATCH ${R}/issues/1`]: () => jsonRes({ number: 1 }),
    });
    expect(await github(f, TOKEN, 'o/r').upsertIssue('T', 'b', [])).toEqual({ number: 1, created: false });
    expect(f.calls.filter((c) => c.method === 'GET').length).toBe(1);
  });

  it('upsertComment: cap hit without a match → posts a new comment', async () => {
    const warn = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    let n = 0;
    const f = fakeFetch((c) =>
      c.method === 'POST'
        ? jsonRes({ id: 5 }, 201)
        : jsonRes([{ id: 1, body: '<!-- m -->', user: HUMAN }], 200, { link: `<${R}/issues/5/comments?per_page=100&page=${++n + 1}>; rel="next"` }),
    );
    expect(await github(f, TOKEN, 'o/r').upsertComment(5, '<!-- m -->', 'b')).toEqual({ id: 5, created: true });
    warn.mockRestore();
  });

  it('findIssue returns our issue number, or null (no create)', async () => {
    const f = route({
      [`GET ${R}/issues?state=open&per_page=100&creator=decant-app%5Bbot%5D`]: () =>
        jsonRes([{ number: 6, title: 'T', user: { login: 'decant-app[bot]', type: 'Bot' } }]),
    });
    const gh = github(f, TOKEN, 'o/r', { selfLogin: 'decant-app[bot]' });
    expect(await gh.findIssue('T')).toBe(6);
    expect(await gh.findIssue('U')).toBeNull();
    expect(f.calls.every((c) => c.method === 'GET')).toBe(true);
  });

  it('closeIssue PATCHes state closed', async () => {
    const f = route({ [`PATCH ${R}/issues/4`]: () => jsonRes({ number: 4 }) });
    await github(f, TOKEN, 'o/r').closeIssue(4);
    expect(JSON.parse(f.calls[0]!.body!)).toMatchObject({ state: 'closed' });
  });

  it('does not follow a next link to another host', async () => {
    const f = route({
      [`GET ${R}/issues?state=open&per_page=100`]: () => jsonRes([], 200, { link: '<https://evil.example/x>; rel="next"' }),
      [`POST ${R}/issues`]: () => jsonRes({ number: 1 }, 201),
    });
    await expect(github(f, TOKEN, 'o/r').upsertIssue('T', 'b', [])).rejects.toThrow(/host/);
    expect(f.calls.some((c) => c.url.startsWith('https://evil'))).toBe(false);
  });
});

describe('commitFiles', () => {
  it('sends createCommitOnBranch with expectedHeadOid and base64 contents', async () => {
    const f = route({
      [`POST ${API}/graphql`]: () => jsonRes({ data: { createCommitOnBranch: { commit: { oid: 'new' } } } }),
    });
    const oid = await github(f, TOKEN, 'o/r').commitFiles('decant/x', 'old', 'subject\n\nbody text', [{ path: 'a/b.json', contents: 'héllo' }]);
    expect(oid).toBe('new');
    const q = JSON.parse(f.calls[0]!.body!);
    expect(q.query).toContain('createCommitOnBranch');
    expect(q.variables.input).toEqual({
      branch: { repositoryNameWithOwner: 'o/r', branchName: 'decant/x' },
      expectedHeadOid: 'old',
      message: { headline: 'subject', body: 'body text' },
      fileChanges: { additions: [{ path: 'a/b.json', contents: Buffer.from('héllo', 'utf8').toString('base64') }] },
    });
  });

  it('throws on GraphQL errors', async () => {
    const f = route({ [`POST ${API}/graphql`]: () => jsonRes({ errors: [{ message: 'Expected branch to point to x' }] }) });
    await expect(github(f, TOKEN, 'o/r').commitFiles('b', 'x', 'm', [])).rejects.toThrow(/Expected branch/);
  });
});

describe('labelAddedByWriter', () => {
  const tl = `${R}/issues/3/timeline?per_page=100`;
  const lb = `GET ${R}/issues/3/labels?per_page=100`;
  const has = (...names: string[]) => () => jsonRes(names.map((name) => ({ name })));
  it('true when the latest add is by a writer and not removed since', async () => {
    const f = route({
      [`GET ${tl}`]: () =>
        jsonRes(
          [
            { event: 'labeled', label: { name: 'decant:reviewed' }, actor: { login: 'mallory' } },
            { event: 'unlabeled', label: { name: 'decant:reviewed' }, actor: { login: 'x' } },
          ],
          200,
          { link: `<${tl}&page=2>; rel="next"` },
        ),
      [`GET ${tl}&page=2`]: () => jsonRes([{ event: 'labeled', label: { name: 'decant:reviewed' }, actor: { login: 'alice' } }]),
      [`GET ${R}/collaborators/alice/permission`]: () => jsonRes({ permission: 'write' }),
      [lb]: has('decant:reviewed'),
    });
    expect(await github(f, TOKEN, 'o/r').labelAddedByWriter(3, 'decant:reviewed')).toBe(true);
  });

  it('false when the adder is read-only, or the label was removed after', async () => {
    const f1 = route({
      [`GET ${tl}`]: () => jsonRes([{ event: 'labeled', label: { name: 'L' }, actor: { login: 'bob' } }]),
      [`GET ${R}/collaborators/bob/permission`]: () => jsonRes({ permission: 'read', role_name: 'triage' }),
      [lb]: has('L'),
    });
    expect(await github(f1, TOKEN, 'o/r').labelAddedByWriter(3, 'L')).toBe(false);
    const f2 = route({
      [`GET ${tl}`]: () =>
        jsonRes([
          { event: 'labeled', label: { name: 'L' }, actor: { login: 'alice' } },
          { event: 'unlabeled', label: { name: 'L' }, actor: { login: 'alice' } },
        ]),
      [lb]: has('L'),
    });
    expect(await github(f2, TOKEN, 'o/r').labelAddedByWriter(3, 'L')).toBe(false);
  });

  it('maintain role counts as a writer', async () => {
    const f = route({
      [`GET ${tl}`]: () => jsonRes([{ event: 'labeled', label: { name: 'L' }, actor: { login: 'm' } }]),
      [`GET ${R}/collaborators/m/permission`]: () => jsonRes({ permission: 'write', role_name: 'maintain' }),
      [lb]: has('L'),
    });
    expect(await github(f, TOKEN, 'o/r').labelAddedByWriter(3, 'L')).toBe(true);
  });

  it('false when the label is not currently on the PR, even if a writer added it', async () => {
    const f = route({
      [`GET ${tl}`]: () => jsonRes([{ event: 'labeled', label: { name: 'L' }, actor: { login: 'alice' } }]),
      [`GET ${R}/collaborators/alice/permission`]: () => jsonRes({ permission: 'admin' }),
      [lb]: has('other'),
    });
    expect(await github(f, TOKEN, 'o/r').labelAddedByWriter(3, 'L')).toBe(false);
  });

  it('still throws (fails closed) when the timeline exceeds the page cap', async () => {
    let n = 0;
    const f = fakeFetch((c) =>
      c.url.includes('/labels')
        ? jsonRes([{ name: 'L' }])
        : jsonRes([], 200, { link: `<${tl}&page=${++n + 1}>; rel="next"` }),
    );
    await expect(github(f, TOKEN, 'o/r').labelAddedByWriter(3, 'L')).rejects.toThrow(/10 pages/);
  });

  it('matches label names case-insensitively', async () => {
    const f = route({
      [`GET ${tl}`]: () =>
        jsonRes([
          { event: 'labeled', label: { name: 'decant:reviewed' }, actor: { login: 'mallory' } },
          { event: 'labeled', label: { name: 'Decant:Reviewed' }, actor: { login: 'alice' } },
        ]),
      [`GET ${R}/collaborators/alice/permission`]: () => jsonRes({ permission: 'write' }),
      [lb]: has('DECANT:REVIEWED'),
    });
    expect(await github(f, TOKEN, 'o/r').labelAddedByWriter(3, 'decant:reviewed')).toBe(true);
  });
});

describe('PRs and branches', () => {
  it('openPr creates the PR then adds labels', async () => {
    const f = route({
      [`POST ${R}/pulls`]: () => jsonRes({ number: 12, node_id: 'PR_n', html_url: 'u' }, 201),
      [`POST ${R}/issues/12/labels`]: () => jsonRes([]),
    });
    const r = await github(f, TOKEN, 'o/r').openPr({ head: 'h', base: 'main', title: 't', body: 'b', labels: ['decant:adopt'] });
    expect(r).toEqual({ number: 12, nodeId: 'PR_n', url: 'u' });
    expect(JSON.parse(f.calls[1]!.body!)).toEqual({ labels: ['decant:adopt'] });
  });

  it('findOpenPr filters by owner:head', async () => {
    const f = route({
      [`GET ${R}/pulls?state=open&head=o%3Adecant%2Fx&per_page=100`]: () =>
        jsonRes([{ number: 4, node_id: 'N', title: 't', body: null, state: 'open', draft: false, user: { login: 'u' }, labels: [{ name: 'a' }], head: { ref: 'decant/x', sha: 's' }, base: { ref: 'main', sha: 'b' } }]),
    });
    const pr = await github(f, TOKEN, 'o/r').findOpenPr('decant/x');
    expect(pr).toMatchObject({ number: 4, nodeId: 'N', headRef: 'decant/x', headSha: 's', baseRef: 'main', labels: ['a'], author: 'u' });
  });

  it('createBranch posts refs/heads; prLabels lists names; enableAutoMerge uses GraphQL', async () => {
    const f = route({
      [`POST ${R}/git/refs`]: () => jsonRes({}, 201),
      [`GET ${R}/issues/2/labels?per_page=100`]: () => jsonRes([{ name: 'x' }]),
      [`POST ${API}/graphql`]: () => jsonRes({ data: { enablePullRequestAutoMerge: { clientMutationId: null } } }),
    });
    const g = github(f, TOKEN, 'o/r');
    await g.createBranch('decant/x', 'abc');
    expect(JSON.parse(f.calls[0]!.body!)).toEqual({ ref: 'refs/heads/decant/x', sha: 'abc' });
    expect(await g.prLabels(2)).toEqual(['x']);
    await g.enableAutoMerge('PR_n', 'SQUASH');
    expect(JSON.parse(f.calls[2]!.body!).variables).toEqual({ id: 'PR_n', method: 'SQUASH' });
  });
});

describe('removeLabel', () => {
  it('DELETEs the encoded label and treats 404 (already gone) as success', async () => {
    const f = route({
      [`DELETE ${R}/issues/5/labels/decant%3Areviewed`]: () => jsonRes([]),
      [`DELETE ${R}/issues/6/labels/decant%3Areviewed`]: () => jsonRes({ message: 'Label does not exist' }, 404),
    });
    const gh = github(f, TOKEN, 'o/r');
    await gh.removeLabel(5, 'decant:reviewed');
    await gh.removeLabel(6, 'decant:reviewed');
    expect(f.calls.map((c) => c.method)).toEqual(['DELETE', 'DELETE']);
  });
});

describe('updateComment (review fix)', () => {
  it('edits our marker comment and returns true; never creates one', async () => {
    const f = route({
      [`GET ${R}/issues/5/comments?per_page=100`]: () => jsonRes([{ id: 2, body: '<!-- m -->\nold', user: BOT }]),
      [`PATCH ${R}/issues/comments/2`]: () => jsonRes({ id: 2 }),
      [`GET ${R}/issues/6/comments?per_page=100`]: () => jsonRes([{ id: 3, body: '<!-- m -->\nold', user: HUMAN }]),
    });
    const gh = github(f, TOKEN, 'o/r');
    expect(await gh.updateComment(5, '<!-- m -->', 'new')).toBe(true);
    expect(await gh.updateComment(6, '<!-- m -->', 'new')).toBe(false);
    expect(f.calls.map((c) => c.method)).toEqual(['GET', 'PATCH', 'GET']);
  });
});
