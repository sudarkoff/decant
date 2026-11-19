export type Ecosystem = 'npm' | 'go';
export interface PackageRef {
  eco: Ecosystem;
  name: string;
  version: string;
}
export interface Env {
  DB: D1Database;
  BUCKET: R2Bucket;
  OPERATOR_TOKEN_HASH: string;
}
export interface Deps {
  fetch: typeof fetch;
  now: () => Date;
  /** Upstream timeout in ms (default 10 000). Tests shorten it. */
  timeoutMs?: number;
}

/** "npm:@s/n@1.2.3", "go:github.com/x/y@v1.2.3" */
export function formatPackageId(p: PackageRef): string {
  return `${p.eco}:${p.name}@${p.version}`;
}

/** Splits on the LAST '@' (names may start with '@'). Returns null if malformed. */
export function parsePackageId(id: string): PackageRef | null {
  const colon = id.indexOf(':');
  if (colon < 0) return null;
  const eco = id.slice(0, colon);
  if (eco !== 'npm' && eco !== 'go') return null;
  const rest = id.slice(colon + 1);
  const at = rest.lastIndexOf('@');
  if (at <= 0 || at === rest.length - 1) return null;
  return { eco, name: rest.slice(0, at), version: rest.slice(at + 1) };
}
