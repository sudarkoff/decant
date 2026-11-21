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
  /** The `# syntax=` frontend image (code BuildKit runs), not a FROM. */
  syntax?: true;
  /** An image pulled by `COPY --from=` or `RUN --mount=…,from=`, not a FROM. */
  via?: 'copy' | 'mount';
  /** ARGs the value was built from: a `--build-arg` at build time can change it (decant sees only defaults). */
  args?: string[];
};

export type ParsedDockerfile = {
  froms: FromLine[];
  errors: string[];
  /** Lines whose image references or --mount values were built from ARGs a --build-arg can override. */
  argLines?: { line: number; args: string[] }[];
};

type Arg = { value: string | undefined };

const DIRECTIVE_RE = /^#\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.+?)\s*$/;
/** The parser directives BuildKit knows; any other `# key=value` is a comment. */
const DIRECTIVES = new Set(['syntax', 'escape', 'check']);
const HEREDOC_INSTRUCTIONS = new Set(['RUN', 'COPY', 'ADD']);
/** Every Dockerfile instruction; any other logical line fails the parse (fail closed). */
const INSTRUCTIONS = new Set([
  'FROM', 'RUN', 'CMD', 'LABEL', 'MAINTAINER', 'EXPOSE', 'ENV', 'ADD', 'COPY', 'ENTRYPOINT',
  'VOLUME', 'USER', 'WORKDIR', 'ARG', 'ONBUILD', 'STOPSIGNAL', 'HEALTHCHECK', 'SHELL',
]);
/** Docker's stage name rule (checked on the lowercased name). */
const STAGE_RE = /^[a-z][a-z0-9_.-]*$/;
/** A heredoc word: optional fd digits, <<, optional -, then a plain name with at most one pair of matching quotes. */
const HEREDOC_WORD = /^(\d*)<<(-?)(["']?)([A-Za-z0-9_.-]+)\3$/;

/**
 * Splits an instruction into shell words, keeping each word's raw text (quotes and escapes included).
 * Null when a quote is never closed.
 */
function shellWords(s: string, esc: string): string[] | null {
  const words: string[] = [];
  let cur = '';
  let inWord = false;
  let q: string | null = null;
  for (let k = 0; k < s.length; k++) {
    const ch = s[k]!;
    if (q === "'") {
      cur += ch;
      if (ch === "'") q = null;
      continue;
    }
    if (ch === esc) {
      cur += ch + (s[k + 1] ?? '');
      k++;
      inWord = true;
      continue;
    }
    if (q === '"') {
      cur += ch;
      if (ch === '"') q = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      q = ch;
      cur += ch;
      inWord = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (inWord) words.push(cur);
      cur = '';
      inWord = false;
      continue;
    }
    cur += ch;
    inWord = true;
  }
  if (q !== null) return null;
  if (inWord) words.push(cur);
  return words;
}

/**
 * The heredocs an instruction opens, in order. Strict, no shell emulation: the line is split into words
 * twice, with `\\` and with the Dockerfile's escape character, and both splits must agree; a word containing
 * `<<` must be exactly `[n]<<[-]NAME` or `[n]<<[-]"NAME"` / `'NAME'` (NAME of letters, digits, `_`, `.`, `-`).
 * Anything else fails closed: decant cannot tell how BuildKit reads the rest of the file.
 */
function heredocs(ins: string, esc: string): { word: string; strip: boolean }[] | string {
  const a = shellWords(ins, '\\');
  const b = esc === '\\' ? a : shellWords(ins, esc);
  if (a === null || b === null || a.length !== b.length || a.some((w, k) => w !== b[k])) return "decant couldn't parse this line (heredoc)";
  const out: { word: string; strip: boolean }[] = [];
  for (const w of a) {
    if (!w.includes('<<')) continue;
    const m = HEREDOC_WORD.exec(w);
    if (!m) return "decant couldn't parse this line (heredoc)";
    out.push({ word: m[4]!, strip: m[2] === '-' });
  }
  return out;
}
const VAR_RE = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))/g;

function unquote(v: string): string {
  return v.length >= 2 && (v[0] === '"' || v[0] === "'") && v.at(-1) === v[0] ? v.slice(1, -1) : v;
}

/** Substitutes ARG references; returns the names that a plain $X / ${X} needed but had no default. */
function substitute(s: string, args: Map<string, Arg>): { text: string; missing: string[]; used: string[] } {
  const missing: string[] = [];
  const used: string[] = [];
  const text = s.replace(VAR_RE, (_m, braced: string | undefined, op: string | undefined, word: string | undefined, bare: string | undefined) => {
    const n = (braced ?? bare)!;
    if (!used.includes(n)) used.push(n);
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
  return { text, missing, used };
}

/**
 * The FROM lines of a Dockerfile. Handles the escape parser directive, line continuations (comment lines
 * inside them are dropped, as BuildKit does), case-insensitive instructions and stage names, and ARG
 * substitution from the defaults of ARGs declared before the first FROM (the only ones FROM can see). A
 * reference decant cannot resolve statically (ARG without a default) is an error, never a guess.
 */
export function parseDockerfile(text: string): ParsedDockerfile {
  const lines = text.replace(/^﻿/, '').split(/\r?\n/);
  const froms: FromLine[] = [];
  const errors: string[] = [];

  // Parser directives, as BuildKit reads them: only at the very top, one per line, known keys only. The
  // first blank line, comment, unknown directive or instruction ends the block; later ones are comments.
  const directives = new Map<string, { value: string; line: number }>();
  let i = 0;
  for (; i < lines.length; i++) {
    const m = DIRECTIVE_RE.exec(lines[i]!.trim());
    if (!m || !DIRECTIVES.has(m[1]!.toLowerCase())) break;
    const k = m[1]!.toLowerCase();
    if (directives.has(k)) errors.push(`line ${i + 1}: parser directive ${k} is repeated`);
    else directives.set(k, { value: m[2]!, line: i + 1 });
  }
  let escape = '\\';
  const esc = directives.get('escape');
  if (esc) {
    if (esc.value === '`' || esc.value === '\\') escape = esc.value;
    else errors.push(`line ${esc.line}: invalid escape directive (BuildKit accepts \\ or \`)`);
  }
  // The syntax directive names the frontend image BuildKit runs to build this file: gated like a FROM.
  const syn = directives.get('syntax');
  if (syn) {
    const ref = parseImageRef(syn.value);
    if (ref) froms.push({ line: syn.line, kind: 'image', raw: syn.value, text: syn.value, ref, syntax: true });
    else {
      errors.push(`line ${syn.line}: syntax=${syn.value}: not a valid image reference`);
      froms.push({ line: syn.line, kind: 'invalid', raw: syn.value, text: '', syntax: true });
    }
  }

  const instructions: { line: number; text: string }[] = [];
  let cur: { line: number; parts: string[] } | null = null;
  for (; i < lines.length; i++) {
    const physical = lines[i]!;
    const t = physical.trim();
    if (t === '' || t.startsWith('#')) continue; // outside, or a comment/blank inside a continuation
    const trimmedEnd = physical.replace(/\s+$/, '');
    const continued = trimmedEnd.endsWith(escape);
    const body = continued ? trimmedEnd.slice(0, -1) : trimmedEnd;
    if (cur === null) cur = { line: i + 1, parts: [] };
    cur.parts.push(body.trim());
    if (continued) continue;
    const ins = { line: cur.line, text: cur.parts.join(' ').trim() };
    cur = null;
    // Every logical line must be an instruction decant knows: anything else (`//` comments, a JSON header,
    // a typo) means decant may not read the file the way BuildKit does.
    const toks = ins.text.split(/\s+/);
    const word = toks[0]!.toUpperCase();
    if (!INSTRUCTIONS.has(word)) {
      errors.push(`line ${ins.line}: decant couldn't parse this line (${toks[0]!.slice(0, 40)} is not a Dockerfile instruction)`);
      continue;
    }
    const inner = word === 'ONBUILD' ? (toks[1] ?? '').toUpperCase() : '';
    if (word === 'ONBUILD' && (!INSTRUCTIONS.has(inner) || inner === 'ONBUILD' || inner === 'FROM' || inner === 'MAINTAINER')) {
      errors.push(`line ${ins.line}: decant couldn't parse this line (ONBUILD ${(toks[1] ?? '').slice(0, 40)} is not allowed)`);
      continue;
    }
    instructions.push(ins);
    // Heredocs (RUN, COPY, ADD): their bodies are not instructions. Skip through each terminator in turn.
    if (!ins.text.includes('<<')) continue;
    if (!HEREDOC_INSTRUCTIONS.has(word) && !HEREDOC_INSTRUCTIONS.has(inner)) continue; // literal text elsewhere
    const docs = heredocs(ins.text, escape);
    if (typeof docs === 'string') {
      errors.push(`line ${ins.line}: ${docs}`);
      return { froms, errors }; // the rest of the file cannot be read with confidence
    }
    for (const d of docs) {
      let j = i + 1;
      while (j < lines.length && (d.strip ? lines[j]!.replace(/^\t+/, '') : lines[j]!) !== d.word) j++;
      if (j >= lines.length) {
        errors.push(`line ${ins.line}: heredoc <<${d.word} is never terminated`);
        return { froms, errors };
      }
      i = j;
    }
  }
  if (cur !== null) errors.push(`line ${cur.line}: decant couldn't parse this line (the file ends inside a line continuation)`);

  // A frontend named anywhere but a recognized `# syntax=` directive (a `// syntax=` line, a JSON header,
  // a syntax line after the directive block) may still be what BuildKit runs: fail closed.
  const firstIns = instructions[0]?.line ?? lines.length + 1;
  for (let k = 0; k < Math.min(firstIns - 1, lines.length); k++) {
    if (k + 1 === syn?.line) continue;
    if (/syntax\s*[=:]|"syntax"/i.test(lines[k]!)) {
      errors.push(`line ${k + 1}: ambiguous frontend (syntax) header; use one "# syntax=<image>@sha256:…" directive at the top of the file`);
    }
  }

  const globals = new Map<string, Arg>();
  let stageArgs = new Map<string, Arg>();
  const argLines: { line: number; args: string[] }[] = [];
  const stages = new Set<string>();
  let seenFrom = false;
  for (const ins of instructions) {
    const m = /^(\S+)\s*(.*)$/.exec(ins.text);
    if (!m) continue;
    const word = m[1]!.toUpperCase();
    const rest = m[2]!;
    if (word === 'ARG') {
      if (seenFrom) {
        // Stage ARGs: in scope for later instructions in this stage (a redeclared global keeps its default).
        for (const tok of rest.split(/\s+/).filter(Boolean)) {
          const eq = tok.indexOf('=');
          const n = eq < 0 ? tok : tok.slice(0, eq);
          stageArgs.set(n, { value: eq < 0 ? globals.get(n)?.value : unquote(tok.slice(eq + 1)) });
        }
        continue; // invisible to FROM
      }
      for (const tok of rest.split(/\s+/).filter(Boolean)) {
        const eq = tok.indexOf('=');
        if (eq < 0) globals.set(tok, { value: undefined });
        else globals.set(tok.slice(0, eq), { value: unquote(tok.slice(eq + 1)) });
      }
      continue;
    }
    // COPY --from=<x> and RUN --mount=…,from=<x> (also under ONBUILD) pull <x> unless it is an earlier stage.
    const inner = word === 'ONBUILD' ? (/^(\S+)\s*(.*)$/.exec(rest) ?? []) : [];
    const kind = word === 'ONBUILD' ? (inner[1] ?? '').toUpperCase() : word;
    if (kind === 'COPY' || kind === 'RUN') {
      let argsUsed: string[] = [];
      for (const src of imageSources(kind, word === 'ONBUILD' ? (inner[2] ?? '') : rest, escape, stageArgs)) {
        if ('argsUsed' in src) {
          argsUsed = [...new Set([...argsUsed, ...src.argsUsed])];
          continue;
        }
        if ('error' in src) {
          errors.push(`line ${ins.line}: decant couldn't parse this line (${src.error})`);
          froms.push({ line: ins.line, kind: 'invalid', raw: rest, text: '' });
          continue;
        }
        const v = src.value;
        if (/^\d+$/.test(v) || (!/[/:@]/.test(v) && stages.has(v.toLowerCase()))) continue; // a stage index or an earlier stage
        const ref = parseImageRef(v);
        if (!ref) {
          errors.push(`line ${ins.line}: ${kind} ${src.flag}=${v}: not an earlier stage or a valid image reference`);
          froms.push({ line: ins.line, kind: 'invalid', raw: rest, text: '' });
          continue;
        }
        froms.push({ line: ins.line, kind: 'image', raw: rest, text: v, ref, via: src.via });
      }
      if (argsUsed.length) argLines.push({ line: ins.line, args: argsUsed });
      continue;
    }
    if (word !== 'FROM') continue;
    seenFrom = true;
    stageArgs = new Map();
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
    if (toks.length === 3 && toks[1]!.toLowerCase() === 'as') {
      stage = toks[2]!.toLowerCase();
      if (!STAGE_RE.test(stage)) {
        bad(`invalid stage name ${toks[2]}`);
        continue;
      }
    }
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
    const base = { line: ins.line, raw: rest, text: image, ...(platform ? { platform } : {}), ...(stage ? { stage } : {}), ...(sub.used.length ? { args: sub.used } : {}) };
    if (image.toLowerCase() === 'scratch') froms.push({ ...base, kind: 'scratch' });
    else if (!/[/:@]/.test(image) && stages.has(image.toLowerCase())) froms.push({ ...base, kind: 'stage' });
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
  // Report in file order (instruction errors are found before FROM errors).
  const lineOf = (e: string) => Number(/^line (\d+)/.exec(e)?.[1] ?? 0);
  return { froms, errors: errors.map((e, k) => ({ e, k })).sort((a, b) => lineOf(a.e) - lineOf(b.e) || a.k - b.k).map((x) => x.e), ...(argLines.length ? { argLines } : {}) };
}

/** The flags BuildKit accepts on COPY and RUN; any other leading `--` token fails closed. */
const KNOWN_FLAGS: Record<'COPY' | 'RUN', Set<string>> = {
  COPY: new Set(['--from', '--chown', '--chmod', '--link', '--parents', '--exclude']),
  RUN: new Set(['--mount', '--network', '--security', '--device']),
};

type Source = { via: 'copy' | 'mount'; flag: string; value: string } | { error: string } | { argsUsed: string[] };

/** BuildKit's predefined platform ARGs, as placeholders with no ',' or '=' (they only matter for the split). */
const PLATFORM_ARGS = new Map(
  ['TARGETPLATFORM', 'TARGETOS', 'TARGETARCH', 'TARGETVARIANT', 'BUILDPLATFORM', 'BUILDOS', 'BUILDARCH', 'BUILDVARIANT'].map((n) => [n, 'platform']),
);

/**
 * Expands variables in a --mount value the way BuildKit does before splitting on commas: platform ARGs as
 * placeholders, others from the ARG defaults in scope. Fails when a variable has no value, or when a value
 * contains ',' or '=' (it could inject a from= at build time).
 */
function expandMount(value: string, scope: Map<string, Arg>): { text: string; used: string[] } | { error: string } {
  const all = new Map<string, Arg>([...[...PLATFORM_ARGS].map(([k, v]) => [k, { value: v }] as [string, Arg]), ...scope]);
  const sub = substitute(value, all);
  if (sub.missing.length) return { error: `--mount uses ${sub.missing.map((n) => `$${n}`).join(', ')} with no value decant can see` };
  for (const n of sub.used) {
    const v = all.get(n)?.value ?? '';
    if (/[,=]/.test(v)) return { error: `--mount: ARG ${n} has a value with ',' or '='` };
  }
  // Also catch a ${X:-a,from=b} default word.
  const raw = value.replace(VAR_RE, '');
  if ((sub.text.match(/[,=]/g) ?? []).length !== (raw.match(/[,=]/g) ?? []).length) return { error: '--mount: a variable expands to \',\' or \'=\'' };
  return { text: sub.text, used: sub.used.filter((n) => !PLATFORM_ARGS.has(n) || scope.has(n)) };
}

/**
 * The `from=` sources of an instruction's leading flags: `COPY --from=<x>`, and `RUN --mount=<k=v,…>` with a
 * `from` key. Fail closed: a leading flag token with quotes, a backslash or the escape character anywhere
 * (name included, e.g. `"--from"=x`, `--fr\om=x`), an unknown flag, a `--from`/`--mount` without `=`, or a
 * value with `$` substitution is an error rather than a guess.
 */
function imageSources(kind: 'COPY' | 'RUN', args: string, esc: string, scope: Map<string, Arg>): Source[] {
  const out: Source[] = [];
  const odd = (t: string) => /["'\\]/.test(t) || t.includes(esc);
  for (const tok of args.split(/\s+/).filter(Boolean)) {
    const flagLike = tok.startsWith('--') || (odd(tok[0]!) && tok.replace(/^["'\\`]+/, '').startsWith('-'));
    if (!flagLike) break; // flags come first
    if (odd(tok)) {
      out.push({ error: `${kind} flag with quotes or escapes` });
      continue;
    }
    const eq = tok.indexOf('=');
    const name = eq < 0 ? tok : tok.slice(0, eq);
    if (!KNOWN_FLAGS[kind].has(name)) {
      out.push({ error: `unknown ${kind} flag ${name.slice(0, 40)}` });
      continue;
    }
    const wanted = kind === 'COPY' ? '--from' : '--mount';
    if (name !== wanted) continue;
    const value = eq < 0 ? '' : tok.slice(eq + 1);
    if (eq < 0) {
      out.push({ error: `${tok.slice(0, 40)}: write ${wanted}=…` });
      continue;
    }
    if (kind === 'COPY') {
      if (value.includes('$')) out.push({ error: '--from with variables' });
      else out.push({ via: 'copy', flag: '--from', value });
      continue;
    }
    const x = expandMount(value, scope);
    if ('error' in x) {
      out.push({ error: x.error });
      continue;
    }
    if (x.used.length) out.push({ argsUsed: x.used });
    for (const kv of x.text.split(',')) {
      const k = kv.indexOf('=');
      if (k < 0 || kv.slice(0, k).toLowerCase() !== 'from') continue;
      if (kv.slice(0, k) !== 'from') out.push({ error: `--mount ${kv.slice(0, k)}=: write from=` });
      else out.push({ via: 'mount', flag: '--mount from', value: kv.slice(k + 1) });
    }
  }
  return out;
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'testdata']);

/**
 * `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `*.dockerfile`, and the Podman/Buildah spellings `Containerfile`,
 * `Containerfile.*`, `*.containerfile` (never an ignore file). Other names (e.g. `Dockerfile-prod`) are not found.
 */
export function isDockerfileName(n: string): boolean {
  if (n.endsWith('.dockerignore') || n.endsWith('.containerignore')) return false;
  for (const base of ['Dockerfile', 'Containerfile']) {
    if (n === base || (n.startsWith(`${base}.`) && n.length > base.length + 1)) return true;
  }
  return ['.Dockerfile', '.dockerfile', '.containerfile'].some((ext) => n.endsWith(ext) && n.length > ext.length);
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
