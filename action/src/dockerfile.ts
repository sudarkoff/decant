import { DIGEST_RE, DOCKER_HUB_ALIASES, isImageRepo } from '../../src/ids';
import type { Fs } from './deps';

/** An image reference, normalized: `name` is the fully qualified repository decant keys images by. */
export type ImageRef = { name: string; registry: string; path: string; tag?: string; digest?: string };

const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;

/**
 * Parses `[registry/]path[:tag][@sha256:…]` the way Docker does: the first component is a registry only
 * if it has a '.' or ':' or is `localhost`; Docker Hub names get `docker.io/` and, for one component,
 * `library/`. Hub aliases (index.docker.io, …) become docker.io. Only sha256 digests are accepted.
 */
export function parseImageRef(ref: string): ImageRef | null {
  if (ref === '' || /\s/.test(ref)) return null;
  const parts = ref.split('@');
  if (parts.length > 2) return null;
  const digest = parts[1];
  if (digest !== undefined && !DIGEST_RE.test(digest)) return null;
  let rest = parts[0]!;
  let tag: string | undefined;
  const colon = rest.lastIndexOf(':');
  if (colon > rest.lastIndexOf('/')) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
    if (!TAG_RE.test(tag)) return null;
  }
  const comps = rest.split('/');
  let registry = 'docker.io';
  const first = comps[0]!;
  if (comps.length > 1 && (first.includes('.') || first.includes(':') || first === 'localhost')) {
    registry = DOCKER_HUB_ALIASES.has(first) ? 'docker.io' : first;
    comps.shift();
  } else if (comps.length === 1 && first.includes('.')) {
    return null; // a bare host (ghcr.io) with no repository
  }
  if (registry === 'docker.io' && comps.length === 1) comps.unshift('library');
  const path = comps.join('/');
  const name = `${registry}/${path}`;
  if (!isImageRepo(name)) return null;
  return { name, registry, path, ...(tag !== undefined ? { tag } : {}), ...(digest !== undefined ? { digest } : {}) };
}

export type FromLine = {
  /** Line number of the FROM (first physical line of a continued instruction). */
  line: number;
  /** scratch, an earlier stage, an image to pull, or a line decant could not read (see errors). */
  kind: 'scratch' | 'stage' | 'image' | 'invalid';
  /** The FROM arguments as written. */
  raw: string;
  /** The image after ARG substitution. */
  text: string;
  platform?: string;
  /** This stage's name (lowercase), from `AS name`. */
  stage?: string;
  ref?: ImageRef;
};

export type ParsedDockerfile = { froms: FromLine[]; errors: string[] };

type Arg = { value: string | undefined };

const DIRECTIVE_RE = /^#\s*([A-Za-z]+)\s*=\s*(.*?)\s*$/;
const VAR_RE = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))/g;

function unquote(v: string): string {
  return v.length >= 2 && (v[0] === '"' || v[0] === "'") && v.at(-1) === v[0] ? v.slice(1, -1) : v;
}

/** Substitutes ARG references; returns the names that a plain $X / ${X} needed but had no default. */
function substitute(s: string, args: Map<string, Arg>): { text: string; missing: string[] } {
  const missing: string[] = [];
  const text = s.replace(VAR_RE, (_m, braced: string | undefined, op: string | undefined, word: string | undefined, bare: string | undefined) => {
    const n = (braced ?? bare)!;
    const v = args.get(n)?.value; // undefined: not declared, or declared without a default
    if (op === undefined) {
      if (v === undefined) {
        if (!missing.includes(n)) missing.push(n);
        return '';
      }
      return v;
    }
    const w = word ?? '';
    switch (op) {
      case ':-':
        return v === undefined || v === '' ? w : v;
      case '-':
        return v === undefined ? w : v;
      case ':+':
        return v !== undefined && v !== '' ? w : '';
      default: // '+'
        return v !== undefined ? w : '';
    }
  });
  return { text, missing };
}

/**
 * The FROM lines of a Dockerfile. Handles the escape parser directive, line continuations (comment lines
 * inside them are dropped, as BuildKit does), case-insensitive instructions and stage names, and ARG
 * substitution from the defaults of ARGs declared before the first FROM (the only ones FROM can see). A
 * reference decant cannot resolve statically (ARG without a default) is an error, never a guess.
 */
export function parseDockerfile(text: string): ParsedDockerfile {
  const lines = text.split(/\r?\n/);
  let escape = '\\';
  let i = 0;
  // Parser directives: only at the very top.
  for (; i < lines.length; i++) {
    const m = DIRECTIVE_RE.exec(lines[i]!.trim());
    if (!m) break;
    if (m[1]!.toLowerCase() === 'escape' && (m[2] === '`' || m[2] === '\\')) escape = m[2]!;
  }
  const instructions: { line: number; text: string }[] = [];
  let cur: { line: number; parts: string[] } | null = null;
  for (; i < lines.length; i++) {
    const physical = lines[i]!;
    const t = physical.trim();
    if (cur === null && (t === '' || t.startsWith('#'))) continue;
    if (cur !== null && (t === '' || t.startsWith('#'))) continue; // comment or blank inside a continuation
    const trimmedEnd = physical.replace(/\s+$/, '');
    const continued = trimmedEnd.endsWith(escape);
    const body = continued ? trimmedEnd.slice(0, -1) : trimmedEnd;
    if (cur === null) cur = { line: i + 1, parts: [] };
    cur.parts.push(body.trim());
    if (!continued) {
      instructions.push({ line: cur.line, text: cur.parts.join(' ').trim() });
      cur = null;
    }
  }
  if (cur !== null) instructions.push({ line: cur.line, text: cur.parts.join(' ').trim() });

  const globals = new Map<string, Arg>();
  const stages = new Set<string>();
  const froms: FromLine[] = [];
  const errors: string[] = [];
  let seenFrom = false;
  for (const ins of instructions) {
    const m = /^(\S+)\s*(.*)$/.exec(ins.text);
    if (!m) continue;
    const word = m[1]!.toUpperCase();
    const rest = m[2]!;
    if (word === 'ARG') {
      if (seenFrom) continue; // stage ARGs are invisible to FROM
      for (const tok of rest.split(/\s+/).filter(Boolean)) {
        const eq = tok.indexOf('=');
        if (eq < 0) globals.set(tok, { value: undefined });
        else globals.set(tok.slice(0, eq), { value: unquote(tok.slice(eq + 1)) });
      }
      continue;
    }
    if (word !== 'FROM') continue;
    seenFrom = true;
    const bad = (why: string) => {
      errors.push(`line ${ins.line}: FROM ${rest}: ${why}`);
      froms.push({ line: ins.line, kind: 'invalid', raw: rest, text: '' });
    };
    const toks = rest.split(/\s+/).filter(Boolean);
    let platform: string | undefined;
    let flagError = false;
    while (toks[0]?.startsWith('--')) {
      const f = toks.shift()!;
      if (/^--platform=\S+$/i.test(f)) platform = f.slice('--platform='.length);
      else flagError = true;
    }
    if (flagError) {
      bad('unsupported FROM flag');
      continue;
    }
    if (toks.length === 0) {
      bad('no image');
      continue;
    }
    let stage: string | undefined;
    if (toks.length === 3 && toks[1]!.toLowerCase() === 'as') stage = toks[2]!.toLowerCase();
    else if (toks.length !== 1) {
      bad('expected FROM [--platform=…] <image> [AS <name>]');
      continue;
    }
    const raw = toks[0]!;
    const sub = substitute(raw, globals);
    if (sub.missing.length) {
      bad(`${sub.missing.map((n) => `ARG ${n}`).join(', ')} has no default; decant cannot tell which image a build would use`);
      continue;
    }
    const image = sub.text;
    const base = { line: ins.line, raw: rest, text: image, ...(platform ? { platform } : {}), ...(stage ? { stage } : {}) };
    if (image.toLowerCase() === 'scratch') froms.push({ ...base, kind: 'scratch' });
    else if (stages.has(image.toLowerCase())) froms.push({ ...base, kind: 'stage' });
    else {
      const ref = parseImageRef(image);
      if (!ref) {
        bad('not a valid image reference');
        if (stage) stages.add(stage);
        continue;
      }
      froms.push({ ...base, kind: 'image', ref });
    }
    if (stage) stages.add(stage);
  }
  return { froms, errors };
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'testdata']);

/** `Dockerfile`, `*.Dockerfile` and `Dockerfile.*` (never a `.dockerignore`). Case-sensitive, like Docker's default. */
export function isDockerfileName(n: string): boolean {
  if (n.endsWith('.dockerignore')) return false;
  return n === 'Dockerfile' || (n.endsWith('.Dockerfile') && n.length > '.Dockerfile'.length) || (n.startsWith('Dockerfile.') && n.length > 'Dockerfile.'.length);
}

/**
 * Dockerfiles under `root` (relative paths, sorted), never through symlinks: symlinked directories and
 * symlinked Dockerfiles are listed in `symlinks` so a gate can refuse them.
 */
export async function findDockerfiles(root: string, fs: Fs): Promise<{ files: string[]; symlinks: string[] }> {
  const files: string[] = [];
  const symlinks: string[] = [];
  const base = root.replace(/\/+$/, '');
  async function walk(rel: string): Promise<void> {
    for (const e of await fs.readdir(rel ? `${base}/${rel}` : base)) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymlink) {
        if ((e.isDir && !SKIP_DIRS.has(e.name)) || isDockerfileName(e.name)) symlinks.push(r);
        continue;
      }
      if (e.isDir) {
        if (!SKIP_DIRS.has(e.name)) await walk(r);
      } else if (isDockerfileName(e.name)) files.push(r);
    }
  }
  await walk('');
  return { files: files.sort(), symlinks: symlinks.sort() };
}
