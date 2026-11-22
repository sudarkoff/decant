export { formatPackageId, parsePackageId } from './ids';
export type { Ecosystem, PackageRef } from './ids';

export interface Env {
  DB: D1Database;
  BUCKET: R2Bucket;
  OPERATOR_TOKEN_HASH: string;
  /** Cloudflare Access team domain, e.g. `myteam.cloudflareaccess.com`. Unset → /dashboard* 404s. */
  ACCESS_TEAM_DOMAIN?: string;
  /** Access application AUD tag. Unset → /dashboard* 404s. */
  ACCESS_AUD?: string;
  /** Docker Hub username for digest verification. Used only with DOCKERHUB_TOKEN; unset → anonymous. */
  DOCKERHUB_USERNAME?: string;
  /** Docker Hub read-only access token (PAT). Sent only to auth.docker.io; never logged. */
  DOCKERHUB_TOKEN?: string;
}
export interface Deps {
  fetch: typeof fetch;
  now: () => Date;
  /** Upstream timeout in ms (default 10 000). Tests shorten it. */
  timeoutMs?: number;
}
