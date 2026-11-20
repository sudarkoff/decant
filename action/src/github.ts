import { warning } from './gh-io';
import { httpError, readJson, request, TIMEOUT_MS } from './http';

const API = 'https://api.github.com';
const MAX_PAGES = 10;
const WRITE_ROLES = new Set(['admin', 'maintain', 'write']);

export type Pr = {
  number: number;
  nodeId: string;
  title: string;
  body: string;
  state: string;
  draft: boolean;
  author: string;
  /** GitHub account type of the author ("User", "Bot"). */
  authorType: string;
  labels: string[];
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
  /** Auto-merge is enabled on the PR. */
  autoMerge: boolean;
};

type RawPr = {
  number: number;
  node_id: string;
  title: string;
  body: string | null;
  state: string;
  draft?: boolean;
  user?: { login?: string; type?: string } | null;
  labels?: { name: string }[];
  head: { ref: string; sha: string };
  base: { ref: string; sha: string };
  auto_merge?: unknown;
};

function toPr(p: RawPr): Pr {
  return {
    number: p.number,
    nodeId: p.node_id,
    title: p.title,
    body: p.body ?? '',
    state: p.state,
    draft: p.draft ?? false,
    author: p.user?.login ?? '',
    authorType: p.user?.type ?? '',
    labels: (p.labels ?? []).map((l) => l.name),
    headRef: p.head.ref,
    headSha: p.head.sha,
    baseRef: p.base.ref,
    baseSha: p.base.sha,
    autoMerge: p.auto_merge !== null && p.auto_merge !== undefined,
  };
}

/** The rel="next" URL of a Link header, if any. */
function nextLink(link: string | null): string | null {
  if (!link) return null;
  for (const part of link.split(',')) {
    const m = /<([^>]+)>\s*;\s*rel="?next"?/.exec(part);
    if (m) return m[1]!;
  }
  return null;
}

export type GitHubClient = ReturnType<typeof github>;

type Author = { login?: string; type?: string } | null | undefined;

export type GitHubOptions = {
  /** The login the token acts as (e.g. "decant-app[bot]"). See `isMine`. */
  selfLogin?: string;
};

/** Minimal GitHub REST + GraphQL client for one repository ("owner/name"). */
export function github(f: typeof fetch, token: string, repo: string, opts: GitHubOptions = {}) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new Error(`repo must be owner/name, got ${JSON.stringify(repo)}`);
  const owner = repo.slice(0, repo.indexOf('/'));
  const R = `/repos/${repo}`;
  const secrets = [token];
  const lc = (s: string | undefined) => (s ?? '').toLowerCase();

  /**
   * Ownership rule for upsertComment/upsertIssue: only items the action itself wrote may be edited,
   * so a human's comment or issue carrying our marker or title is never hijacked.
   * With `selfLogin`, the author's login must equal it. Without it (installation tokens cannot
   * look themselves up), the author must be a Bot account.
   */
  const isMine = (u: Author) => (opts.selfLogin ? u?.login === opts.selfLogin : u?.type === 'Bot');

  async function rest(method: string, pathOrUrl: string, body?: unknown): Promise<Response> {
    const url = pathOrUrl.startsWith('https://') ? pathOrUrl : `${API}${pathOrUrl}`;
    const u = new URL(url);
    if (u.origin !== API) throw new Error(`GitHub: refusing to send credentials to another host (${u.host})`);
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'decant-action',
    };
    if (body !== undefined) headers['content-type'] = 'application/json';
    const label = `GitHub ${method} ${u.pathname}`;
    const res = await request(f, url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }, { label, timeoutMs: TIMEOUT_MS, secrets });
    if (!res.ok) throw await httpError(res, { label, secrets });
    return res;
  }

  async function json<T>(method: string, path: string, body?: unknown): Promise<T> {
    return readJson<T>(await rest(method, path, body), `GitHub ${method} ${path}`);
  }

  /**
   * Pages (following Link rel="next") until an item satisfies `match`; returns it, or null when the
   * pages run out. `capped` is true when MAX_PAGES was reached with a next page left (no throw:
   * used where an attacker could pad the list, and a miss just means "create a new one").
   */
  async function findPaged<T>(path: string, match: (x: T) => boolean): Promise<{ hit: T | null; capped: boolean }> {
    let url: string | null = path;
    for (let page = 0; url; page++) {
      if (page >= MAX_PAGES) return { hit: null, capped: true };
      const res = await rest('GET', url);
      const hit = (await readJson<T[]>(res, `GitHub GET ${path}`)).find(match);
      if (hit) return { hit, capped: false };
      url = nextLink(res.headers.get('link'));
    }
    return { hit: null, capped: false };
  }

  /** GETs every page (following Link rel="next"); throws past MAX_PAGES (fails closed). */
  async function paged<T>(path: string): Promise<T[]> {
    const out: T[] = [];
    let url: string | null = path;
    for (let page = 0; url; page++) {
      if (page >= MAX_PAGES) throw new Error(`GitHub GET ${path.split('?')[0]}: more than ${MAX_PAGES} pages`);
      const res = await rest('GET', url);
      out.push(...(await readJson<T[]>(res, `GitHub GET ${path}`)));
      url = nextLink(res.headers.get('link'));
    }
    return out;
  }

  async function graphql<T>(query: string, variables: Record<string, unknown>): Promise<T> {
    const r = await json<{ data?: T; errors?: { message?: string }[] }>('POST', '/graphql', { query, variables });
    if (r.errors?.length) throw new Error(`GitHub GraphQL: ${r.errors.map((e) => e.message ?? 'error').join('; ')}`.replaceAll(token, '***'));
    if (!r.data) throw new Error('GitHub GraphQL: no data');
    return r.data;
  }

  async function writerCanAct(login: string): Promise<boolean> {
    let r: { permission?: string; role_name?: string };
    try {
      r = await json('GET', `${R}/collaborators/${encodeURIComponent(login)}/permission`);
    } catch (e) {
      if (/HTTP 404/.test((e as Error).message)) return false;
      throw e;
    }
    return WRITE_ROLES.has(r.permission ?? '') || WRITE_ROLES.has(r.role_name ?? '');
  }

  /** PATCHes the first comment of ours containing `marker`; returns its id, or null if none. */
  async function editMine(n: number, marker: string, text: string): Promise<number | null> {
    const { hit, capped } = await findPaged<{ id: number; body?: string; user?: Author }>(
      `${R}/issues/${n}/comments?per_page=100`,
      (c) => isMine(c.user) && (c.body ?? '').includes(marker),
    );
    if (capped) warning(`decant: #${n} has more than ${MAX_PAGES} pages of comments; the report comment was not found`);
    if (!hit) return null;
    await rest('PATCH', `${R}/issues/comments/${hit.id}`, { body: text });
    return hit.id;
  }

  async function findIssue(title: string, labels: string[] = []): Promise<number | null> {
    type Issue = { number: number; title: string; pull_request?: unknown; user?: Author };
    const match = (i: Issue) => i.pull_request === undefined && i.title === title && isMine(i.user);
    const list = `${R}/issues?state=open&per_page=100`;
    // Narrowest query first: our own issues (selfLogin), else our labels, falling back to all open issues.
    const queries = opts.selfLogin
      ? [`${list}&creator=${encodeURIComponent(opts.selfLogin)}`]
      : labels.length
        ? [`${list}&labels=${encodeURIComponent(labels.join(','))}`, list]
        : [list];
    for (const q of queries) {
      const r = await findPaged<Issue>(q, match);
      if (r.capped) warning(`decant: more than ${MAX_PAGES} pages of open issues; may create a duplicate of "${title}"`);
      if (r.hit) return r.hit.number;
    }
    return null;
  }

  return {
    graphql,

    /** True if `u` is the account this client acts as (see isMine above). */
    isMine: (u: Author) => isMine(u),

    /**
     * The files changed between `base` and `head` if `head` is exactly one commit on top of `base`,
     * authored by us; otherwise null.
     */
    async ownSingleCommit(base: string, head: string): Promise<string[] | null> {
      type Commit = { sha: string; author?: Author; parents?: { sha: string }[] };
      const r = await json<{ status?: string; ahead_by?: number; behind_by?: number; commits?: Commit[]; files?: { filename: string }[] }>(
        'GET',
        `${R}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`,
      );
      if (r.status !== 'ahead' || r.ahead_by !== 1 || r.behind_by !== 0 || r.commits?.length !== 1) return null;
      const c = r.commits[0]!;
      if (!isMine(c.author) || c.parents?.length !== 1 || c.parents[0]!.sha !== base) return null;
      return (r.files ?? []).map((f) => f.filename);
    },

    async defaultBranch(): Promise<string> {
      return (await json<{ default_branch: string }>('GET', R)).default_branch;
    },

    async getPr(n: number): Promise<Pr> {
      return toPr(await json<RawPr>('GET', `${R}/pulls/${n}`));
    },

    /** Removes `label` from issue/PR `n`; a label that is already gone (404) is not an error. */
    async removeLabel(n: number, label: string): Promise<void> {
      try {
        await rest('DELETE', `${R}/issues/${n}/labels/${encodeURIComponent(label)}`);
      } catch (e) {
        if (!/HTTP 404/.test((e as Error).message)) throw e;
      }
    },

    async prLabels(n: number): Promise<string[]> {
      return (await paged<{ name: string }>(`${R}/issues/${n}/labels?per_page=100`)).map((l) => l.name);
    },

    /**
     * True if `label` is on the PR now, its most recent `labeled` event has no later `unlabeled`,
     * and that event's actor has admin, maintain or write permission. Label names compare case-insensitively.
     */
    async labelAddedByWriter(n: number, label: string): Promise<boolean> {
      const want = lc(label);
      const current = await paged<{ name: string }>(`${R}/issues/${n}/labels?per_page=100`);
      if (!current.some((l) => lc(l.name) === want)) return false;
      const events = await paged<{ event?: string; label?: { name?: string }; actor?: { login?: string } | null }>(
        `${R}/issues/${n}/timeline?per_page=100`,
      );
      let adder: string | null = null;
      for (const e of events) {
        if (lc(e.label?.name) !== want) continue;
        if (e.event === 'labeled') adder = e.actor?.login ?? null;
        else if (e.event === 'unlabeled') adder = null;
      }
      return adder !== null && writerCanAct(adder);
    },

    /** Edits the first comment containing `marker`, else posts one. The body always carries the marker. */
    async upsertComment(n: number, marker: string, body: string): Promise<{ id: number; created: boolean }> {
      const text = body.includes(marker) ? body : `${marker}\n${body}`;
      const id = await editMine(n, marker, text);
      if (id !== null) return { id, created: false };
      const c = await json<{ id: number }>('POST', `${R}/issues/${n}/comments`, { body: text });
      return { id: c.id, created: true };
    },

    /** Edits our comment containing `marker` if there is one; never creates. True if edited. */
    async updateComment(n: number, marker: string, body: string): Promise<boolean> {
      return (await editMine(n, marker, body.includes(marker) ? body : `${marker}\n${body}`)) !== null;
    },

    async findOpenPr(head: string): Promise<Pr | null> {
      const q = `head=${encodeURIComponent(`${owner}:${head}`)}`;
      const prs = await json<RawPr[]>('GET', `${R}/pulls?state=open&${q}&per_page=100`);
      return prs[0] ? toPr(prs[0]) : null;
    },

    /** The most recently closed, unmerged PR from `head` (a declined change), or null. */
    async findClosedUnmergedPr(head: string): Promise<{ number: number; body: string } | null> {
      const q = `head=${encodeURIComponent(`${owner}:${head}`)}`;
      const prs = await json<{ number: number; merged_at?: string | null; closed_at?: string | null; body?: string | null }[]>(
        'GET',
        `${R}/pulls?state=closed&${q}&per_page=100`,
      );
      const declined = prs.filter((p) => !p.merged_at).sort((a, b) => (b.closed_at ?? '').localeCompare(a.closed_at ?? '') || b.number - a.number);
      return declined[0] ? { number: declined[0].number, body: declined[0].body ?? '' } : null;
    },

    /** Head commit sha of branch `name`. */
    async branchHead(name: string): Promise<string> {
      const r = await json<{ object: { sha: string } }>('GET', `${R}/git/ref/heads/${name.split('/').map(encodeURIComponent).join('/')}`);
      return r.object.sha;
    },

    /** Force-moves branch `name` to `sha`. */
    async updateRef(name: string, sha: string): Promise<void> {
      await rest('PATCH', `${R}/git/refs/heads/${name.split('/').map(encodeURIComponent).join('/')}`, { sha, force: true });
    },

    async updatePr(n: number, p: { body: string; title?: string }): Promise<void> {
      await rest('PATCH', `${R}/pulls/${n}`, p.title === undefined ? { body: p.body } : { title: p.title, body: p.body });
    },

    /** Adds `labels` to issue/PR `n` (existing labels are kept). */
    async addLabels(n: number, labels: string[]): Promise<void> {
      await rest('POST', `${R}/issues/${n}/labels`, { labels });
    },

    /** UTF-8 contents of `path` at `ref`; null if it does not exist there. */
    async fileAt(path: string, ref: string): Promise<string | null> {
      try {
        const r = await json<{ content?: string; encoding?: string }>('GET', `${R}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(ref)}`);
        if (r.encoding !== 'base64' || typeof r.content !== 'string') return null;
        return Buffer.from(r.content, 'base64').toString('utf8');
      } catch (e) {
        if (/HTTP 404/.test((e as Error).message)) return null;
        throw e;
      }
    },

    async createBranch(name: string, fromSha: string): Promise<void> {
      await rest('POST', `${R}/git/refs`, { ref: `refs/heads/${name}`, sha: fromSha });
    },

    /** One signed commit via createCommitOnBranch. Fails if the branch head is not expectedHeadOid. Returns the new oid. */
    async commitFiles(branch: string, expectedHeadOid: string, message: string, files: { path: string; contents: string }[]): Promise<string> {
      const nl = message.indexOf('\n');
      const headline = nl < 0 ? message : message.slice(0, nl);
      const rest_ = nl < 0 ? '' : message.slice(nl + 1).replace(/^\n+/, '');
      const input = {
        branch: { repositoryNameWithOwner: repo, branchName: branch },
        expectedHeadOid,
        message: rest_ ? { headline, body: rest_ } : { headline },
        fileChanges: { additions: files.map((x) => ({ path: x.path, contents: Buffer.from(x.contents, 'utf8').toString('base64') })) },
      };
      const d = await graphql<{ createCommitOnBranch: { commit: { oid: string } } }>(
        'mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }',
        { input },
      );
      return d.createCommitOnBranch.commit.oid;
    },

    async openPr(p: { head: string; base: string; title: string; body: string; labels?: string[] }): Promise<{ number: number; nodeId: string; url: string }> {
      const pr = await json<{ number: number; node_id: string; html_url: string }>('POST', `${R}/pulls`, {
        head: p.head,
        base: p.base,
        title: p.title,
        body: p.body,
      });
      if (p.labels?.length) await rest('POST', `${R}/issues/${pr.number}/labels`, { labels: p.labels });
      return { number: pr.number, nodeId: pr.node_id, url: pr.html_url };
    },

    async enableAutoMerge(prNodeId: string, method: 'SQUASH' | 'MERGE' | 'REBASE' = 'SQUASH'): Promise<void> {
      await graphql(
        'mutation($id: ID!, $method: PullRequestMergeMethod!) { enablePullRequestAutoMerge(input: { pullRequestId: $id, mergeMethod: $method }) { clientMutationId } }',
        { id: prNodeId, method },
      );
    },

    async disableAutoMerge(prNodeId: string): Promise<void> {
      await graphql('mutation($id: ID!) { disablePullRequestAutoMerge(input: { pullRequestId: $id }) { clientMutationId } }', { id: prNodeId });
    },

    /** Our open issue titled exactly `title` (see upsertIssue for the search order); null if none. */
    findIssue,

    /**
     * Updates the body of our open issue titled exactly `title`, else creates it with `labels`.
     * Matches on title and author only (not labels), so a removed label never causes a duplicate.
     */
    async upsertIssue(title: string, body: string, labels: string[]): Promise<{ number: number; created: boolean }> {
      const hit = await findIssue(title, labels);
      if (hit !== null) {
        await rest('PATCH', `${R}/issues/${hit}`, { body });
        return { number: hit, created: false };
      }
      const i = await json<{ number: number }>('POST', `${R}/issues`, { title, body, labels });
      return { number: i.number, created: true };
    },

    async closeIssue(n: number): Promise<void> {
      await rest('PATCH', `${R}/issues/${n}`, { state: 'closed', state_reason: 'completed' });
    },
  };
}
