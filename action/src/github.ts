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
  labels: string[];
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
};

type RawPr = {
  number: number;
  node_id: string;
  title: string;
  body: string | null;
  state: string;
  draft?: boolean;
  user?: { login?: string } | null;
  labels?: { name: string }[];
  head: { ref: string; sha: string };
  base: { ref: string; sha: string };
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
    labels: (p.labels ?? []).map((l) => l.name),
    headRef: p.head.ref,
    headSha: p.head.sha,
    baseRef: p.base.ref,
    baseSha: p.base.sha,
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

/** Minimal GitHub REST + GraphQL client for one repository ("owner/name"). */
export function github(f: typeof fetch, token: string, repo: string) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new Error(`repo must be owner/name, got ${JSON.stringify(repo)}`);
  const owner = repo.slice(0, repo.indexOf('/'));
  const R = `/repos/${repo}`;
  const secrets = [token];

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

  /** GETs every page (following Link rel="next", at most MAX_PAGES). */
  async function paged<T>(path: string): Promise<T[]> {
    const out: T[] = [];
    let url: string | null = path;
    for (let page = 0; url && page < MAX_PAGES; page++) {
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

  return {
    graphql,

    async defaultBranch(): Promise<string> {
      return (await json<{ default_branch: string }>('GET', R)).default_branch;
    },

    async getPr(n: number): Promise<Pr> {
      return toPr(await json<RawPr>('GET', `${R}/pulls/${n}`));
    },

    async prLabels(n: number): Promise<string[]> {
      return (await paged<{ name: string }>(`${R}/issues/${n}/labels?per_page=100`)).map((l) => l.name);
    },

    /**
     * True if `label` is currently applied by its most recent `labeled` event (no later `unlabeled`)
     * and that event's actor has admin, maintain or write permission on the repo.
     */
    async labelAddedByWriter(n: number, label: string): Promise<boolean> {
      const events = await paged<{ event?: string; label?: { name?: string }; actor?: { login?: string } | null }>(
        `${R}/issues/${n}/timeline?per_page=100`,
      );
      let adder: string | null = null;
      for (const e of events) {
        if (e.label?.name !== label) continue;
        if (e.event === 'labeled') adder = e.actor?.login ?? null;
        else if (e.event === 'unlabeled') adder = null;
      }
      return adder !== null && writerCanAct(adder);
    },

    /** Edits the first comment containing `marker`, else posts one. The body always carries the marker. */
    async upsertComment(n: number, marker: string, body: string): Promise<{ id: number; created: boolean }> {
      const text = body.includes(marker) ? body : `${marker}\n${body}`;
      const comments = await paged<{ id: number; body?: string }>(`${R}/issues/${n}/comments?per_page=100`);
      const hit = comments.find((c) => (c.body ?? '').includes(marker));
      if (hit) {
        await rest('PATCH', `${R}/issues/comments/${hit.id}`, { body: text });
        return { id: hit.id, created: false };
      }
      const c = await json<{ id: number }>('POST', `${R}/issues/${n}/comments`, { body: text });
      return { id: c.id, created: true };
    },

    async findOpenPr(head: string): Promise<Pr | null> {
      const q = `head=${encodeURIComponent(`${owner}:${head}`)}`;
      const prs = await json<RawPr[]>('GET', `${R}/pulls?state=open&${q}&per_page=100`);
      return prs[0] ? toPr(prs[0]) : null;
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

    /** Updates the body of the open issue titled exactly `title` (filtered by `labels`), else creates it. */
    async upsertIssue(title: string, body: string, labels: string[]): Promise<{ number: number; created: boolean }> {
      const lq = labels.length ? `&labels=${encodeURIComponent(labels.join(','))}` : '';
      const issues = await paged<{ number: number; title: string; pull_request?: unknown }>(`${R}/issues?state=open&per_page=100${lq}`);
      const hit = issues.find((i) => i.pull_request === undefined && i.title === title);
      if (hit) {
        await rest('PATCH', `${R}/issues/${hit.number}`, { body });
        return { number: hit.number, created: false };
      }
      const i = await json<{ number: number }>('POST', `${R}/issues`, { title, body, labels });
      return { number: i.number, created: true };
    },

    async closeIssue(n: number): Promise<void> {
      await rest('PATCH', `${R}/issues/${n}`, { state: 'closed', state_reason: 'completed' });
    },
  };
}
