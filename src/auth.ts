import type { Env } from './types';

export type AuthCtx = { kind: 'operator' } | { kind: 'read' | 'ci'; projectId: string };

/** Per-request context handed to the npm/go handlers. base = origin + prefix, e.g. https://h/r/pr-12 */
export interface RequestCtx {
  projectId: string;
  ref: string | null;
  base: string;
}

function b64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function newToken(kind: 'read' | 'ci' | 'op'): string {
  return `dk_${kind}_${b64url(crypto.getRandomValues(new Uint8Array(32)))}`;
}

export async function hashToken(t: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Constant-time for equal-length strings; no early exit. */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function extractToken(req: Request): string | null {
  const h = req.headers.get('authorization');
  if (!h) return null;
  const m = /^(Bearer|Basic)\s+(\S+)\s*$/i.exec(h);
  if (!m) return null;
  if (m[1]!.toLowerCase() === 'bearer') return m[2]!;
  try {
    const decoded = atob(m[2]!);
    const i = decoded.indexOf(':');
    return i < 0 ? null : decoded.slice(i + 1);
  } catch {
    return null;
  }
}

export async function authenticate(req: Request, env: Env): Promise<AuthCtx | null> {
  const token = extractToken(req);
  if (!token) return null;
  const hash = await hashToken(token);
  const op = env.OPERATOR_TOKEN_HASH;
  if (op && constantTimeEqual(hash, op)) return { kind: 'operator' };
  const row = await env.DB.prepare('SELECT project_id, kind FROM tokens WHERE hash = ?')
    .bind(hash)
    .first<{ project_id: string; kind: 'read' | 'ci' }>();
  if (!row) return null;
  return { kind: row.kind, projectId: row.project_id };
}
