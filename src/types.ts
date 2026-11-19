export { formatPackageId, parsePackageId } from './ids';
export type { Ecosystem, PackageRef } from './ids';

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
