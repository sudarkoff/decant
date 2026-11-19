// Pure helpers for the operator CLI. No `node:` imports: this file is tested in the Workers pool.
// Token format and hashing mirror src/auth.ts (kept separate so the CLI has no src/ dependency).

export type CliEnv = Record<string, string | undefined>;

export const USAGE = `usage:
  decant project create <id>
  decant token create <project> <read|ci|sync>
  decant op-token

env: DECANT_URL, DECANT_OPERATOR_TOKEN`;

function b64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A new operator token and the SHA-256 lowercase hex to store as OPERATOR_TOKEN_HASH. */
export async function makeOperatorToken(): Promise<{ token: string; hash: string }> {
  const token = `dk_op_${b64url(crypto.getRandomValues(new Uint8Array(32)))}`;
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  const hash = [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return { token, hash };
}

/** Builds the admin API request for a CLI invocation (not including `op-token`, which is local). */
export function buildRequest(argv: string[], env: CliEnv): Request | { error: string } {
  const [cmd, sub, a, b] = argv;
  let path: string;
  let body: Record<string, string>;
  if (cmd === 'project' && sub === 'create' && a && argv.length === 3) {
    path = '/api/projects';
    body = { id: a };
  } else if (cmd === 'token' && sub === 'create' && a && b && argv.length === 4) {
    if (b !== 'read' && b !== 'ci' && b !== 'sync') return { error: 'kind must be read, ci or sync' };
    path = `/api/projects/${encodeURIComponent(a)}/tokens`;
    body = { kind: b };
  } else {
    return { error: USAGE };
  }
  const base = env.DECANT_URL;
  if (!base) return { error: 'DECANT_URL is not set' };
  const token = env.DECANT_OPERATOR_TOKEN;
  if (!token) return { error: 'DECANT_OPERATOR_TOKEN is not set' };
  return new Request(base.replace(/\/+$/, '') + path, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}
