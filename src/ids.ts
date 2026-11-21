export type Ecosystem = 'npm' | 'go' | 'docker';
export interface PackageRef {
  eco: Ecosystem;
  name: string;
  version: string;
}

/** "npm:@s/n@1.2.3", "go:github.com/x/y@v1.2.3", "docker:docker.io/library/node@sha256:…" */
export function formatPackageId(p: PackageRef): string {
  return `${p.eco}:${p.name}@${p.version}`;
}

/** Splits on the LAST '@' (names may start with '@'). Returns null if malformed. */
export function parsePackageId(id: string): PackageRef | null {
  const colon = id.indexOf(':');
  if (colon < 0) return null;
  const eco = id.slice(0, colon);
  if (eco !== 'npm' && eco !== 'go' && eco !== 'docker') return null;
  const rest = id.slice(colon + 1);
  const at = rest.lastIndexOf('@');
  if (at <= 0 || at === rest.length - 1) return null;
  const name = rest.slice(0, at);
  const version = rest.slice(at + 1);
  if (eco === 'docker' && !(isImageRepo(name) && DIGEST_RE.test(version))) return null;
  return { eco, name, version };
}

/** A manifest digest as written in FROM: sha256 only, lowercase hex. */
export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/** Hosts that are other names for Docker Hub; a normalized repository always says docker.io. */
export const DOCKER_HUB_ALIASES = new Set(['index.docker.io', 'registry-1.docker.io', 'registry.hub.docker.com']);

const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]{1,5})?$/;
/** One path component of an OCI repository name (distribution spec). */
const PATH_RE = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;

/**
 * A fully qualified image repository: `host/path`, where host has a dot or a port (or is localhost), so it
 * can never be mistaken for a Docker Hub namespace. Docker Hub is always `docker.io/<ns>/<name>` (official
 * images under `library/`). At most 255 characters.
 */
export function isImageRepo(s: string): boolean {
  if (s.length > 255) return false;
  const parts = s.split('/');
  if (parts.length < 2) return false;
  const host = parts[0]!;
  if (!HOST_RE.test(host) || !(host.includes('.') || host.includes(':') || host === 'localhost')) return false;
  if (DOCKER_HUB_ALIASES.has(host)) return false;
  if (host === 'docker.io' && parts.length !== 3) return false;
  return parts.slice(1).every((p) => PATH_RE.test(p));
}

/** A decant project id: what the Worker accepts on project creation and in policy.project. */
export const PROJECT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
