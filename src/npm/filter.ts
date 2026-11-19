import { compareVersions, isPrerelease, parseVersion } from '../semver';

export interface Packument {
  name: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  versions: Record<string, any>;
  'dist-tags'?: Record<string, string>;
  time?: Record<string, string>;
  modified?: string;
  [k: string]: unknown;
}

/** Pure: returns a filtered copy of a full or abbreviated packument. */
export function filterPackument(doc: Packument, allowed: Set<string>, tarballBase: string): Packument {
  const out = structuredClone(doc);
  out.versions ??= {}; // unpublished packages have time.unpublished and no versions
  const basename = out.name.split('/').pop() as string;

  for (const v of Object.keys(out.versions ?? {})) {
    if (!allowed.has(v)) {
      delete out.versions[v];
      continue;
    }
    const dist = out.versions[v]?.dist;
    if (dist && typeof dist === 'object') {
      dist.tarball = `${tarballBase}/${out.name}/-/${basename}-${v}.tgz`;
    }
  }

  if (out.time) {
    let newest: string | null = null;
    for (const k of Object.keys(out.time)) {
      if (k === 'created' || k === 'modified') continue;
      if (!allowed.has(k) || !(k in out.versions)) {
        delete out.time[k];
        continue;
      }
      const t = out.time[k];
      if (newest === null || Date.parse(t) > Date.parse(newest)) newest = t;
    }
    if (newest !== null) out.time.modified = newest;
    else delete out.time.modified;
  }

  const tags: Record<string, string> = {};
  for (const [tag, target] of Object.entries(out['dist-tags'] ?? {})) {
    if (tag !== 'latest' && allowed.has(target) && target in out.versions) tags[tag] = target;
  }
  const candidates = Object.keys(out.versions).filter((v) => parseVersion(v, 'npm') !== null);
  const best = (list: string[]) => list.reduce<string | null>((a, b) => (a === null || compareVersions(b, a, 'npm') > 0 ? b : a), null);
  const latest = best(candidates.filter((v) => !isPrerelease(v, 'npm'))) ?? best(candidates);
  if (latest !== null) tags.latest = latest;
  out['dist-tags'] = tags;

  return out;
}
