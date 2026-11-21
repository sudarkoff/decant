import { describe, expect, it } from 'vitest';
import { findDockerfiles, isDockerfileName, parseDockerfile, parseImageRef } from '../src/dockerfile';
import { memFs } from './fakes';

const D = `sha256:${'a'.repeat(64)}`;
const E = `sha256:${'b'.repeat(64)}`;
const HD = (line: number) => `line ${line}: decant couldn't parse this line (heredoc)`;

describe('parseImageRef', () => {
  it('normalizes Docker Hub short names and aliases', () => {
    expect(parseImageRef('node')).toEqual({ name: 'docker.io/library/node', registry: 'docker.io', path: 'library/node' });
    expect(parseImageRef('node:22')).toMatchObject({ name: 'docker.io/library/node', tag: '22' });
    expect(parseImageRef('bitnami/redis:7.2')).toMatchObject({ name: 'docker.io/bitnami/redis', tag: '7.2' });
    expect(parseImageRef('docker.io/node')).toMatchObject({ name: 'docker.io/library/node' });
    expect(parseImageRef('index.docker.io/library/node')).toMatchObject({ name: 'docker.io/library/node', registry: 'docker.io' });
    expect(parseImageRef('registry-1.docker.io/library/node')).toMatchObject({ name: 'docker.io/library/node' });
  });

  it('reads tag and digest; the tag is documentation when a digest is present', () => {
    expect(parseImageRef(`node:22-alpine@${D}`)).toEqual({ name: 'docker.io/library/node', registry: 'docker.io', path: 'library/node', tag: '22-alpine', digest: D });
    expect(parseImageRef(`ghcr.io/acme/api@${D}`)).toEqual({ name: 'ghcr.io/acme/api', registry: 'ghcr.io', path: 'acme/api', digest: D });
    expect(parseImageRef(`localhost:5000/x/y:1@${D}`)).toMatchObject({ name: 'localhost:5000/x/y', registry: 'localhost:5000', tag: '1' });
    expect(parseImageRef('registry.example.com:5000/team/app:2')).toMatchObject({ registry: 'registry.example.com:5000', path: 'team/app', tag: '2' });
  });

  it('rejects malformed references', () => {
    for (const r of ['', 'Node', 'node:', `node@sha256:${'a'.repeat(63)}`, 'node@sha512:abc', 'node@md5:abc', 'a//b', '-x', 'node:bad tag', `node@${D}@${D}`, 'ghcr.io', 'x/Y']) {
      expect(parseImageRef(r), r).toBeNull();
    }
  });
});

describe('parseDockerfile', () => {
  it('classifies FROM lines: scratch, earlier stages (case-insensitive), pinned and unpinned images', () => {
    const r = parseDockerfile(
      [
        `FROM node:22@${D} AS Build`,
        'RUN npm ci',
        'from build as test',
        'FROM scratch',
        `FROM --platform=linux/arm64 ghcr.io/acme/base@${E}`,
        'FROM alpine:3.20',
        'FROM later',
        'FROM node AS later',
      ].join('\n'),
    );
    expect(r.errors).toEqual([]);
    expect(r.froms.map((f) => [f.line, f.kind])).toEqual([
      [1, 'image'],
      [3, 'stage'],
      [4, 'scratch'],
      [5, 'image'],
      [6, 'image'],
      [7, 'image'], // a stage defined later is not a stage reference: it is pulled as an image
      [8, 'image'],
    ]);
    expect(r.froms[0]).toMatchObject({ text: `node:22@${D}`, ref: { name: 'docker.io/library/node', tag: '22', digest: D }, stage: 'build' });
    expect(r.froms[3]).toMatchObject({ platform: 'linux/arm64', ref: { name: 'ghcr.io/acme/base', digest: E } });
    expect(r.froms[4]!.ref).toMatchObject({ name: 'docker.io/library/alpine', tag: '3.20' });
    expect(r.froms[4]!.ref!.digest).toBeUndefined();
  });

  it('substitutes global ARG defaults: $X, ${X}, ${X:-default}, ${X-default}, ${X:+alt}', () => {
    const r = parseDockerfile(
      [
        'ARG BASE=node',
        'ARG TAG=22',
        `ARG DIGEST=${D}`,
        'ARG EMPTY=',
        'ARG UNSET',
        'FROM $BASE:${TAG}@${DIGEST}',
        `FROM \${UNSET:-node}:\${EMPTY:-20}@${D}`,
        `FROM \${UNSET-alpine}@${E}`,
        `FROM node\${TAG:+:}\${TAG}@${E}`,
      ].join('\n'),
    );
    expect(r.errors).toEqual([]);
    expect(r.froms.map((f) => f.text)).toEqual([`node:22@${D}`, `node:20@${D}`, `alpine@${E}`, `node:22@${E}`]);
    expect(r.froms.map((f) => f.args)).toEqual([['BASE', 'TAG', 'DIGEST'], ['UNSET', 'EMPTY'], ['UNSET'], ['TAG']]);
    expect(parseDockerfile(`FROM node@${D}`).froms[0]!.args).toBeUndefined();
  });

  it('an ARG without a default, an unknown ARG, or a stage-local ARG cannot be resolved statically: error', () => {
    const r = parseDockerfile(['ARG BASE', 'FROM ${BASE}', 'FROM $NOPE', 'FROM node AS a', 'ARG LOCAL=alpine', 'FROM $LOCAL'].join('\n'));
    expect(r.errors).toEqual([
      'line 2: FROM ${BASE}: ARG BASE has no default; decant cannot tell which image a build would use',
      'line 3: FROM $NOPE: ARG NOPE has no default; decant cannot tell which image a build would use',
      'line 6: FROM $LOCAL: ARG LOCAL has no default; decant cannot tell which image a build would use',
    ]);
  });

  it('joins line continuations, skips comments (also inside continuations), keeps the first line number', () => {
    const r = parseDockerfile(
      [
        '# a leading comment',
        '  # a comment',
        'FROM \\',
        '# comment inside the continuation',
        `  node:22@${D} \\`,
        '  AS base',
        'RUN echo hi \\',
        '  && echo FROM alpine',
      ].join('\r\n'),
    );
    expect(r.errors).toEqual([]);
    expect(r.froms).toHaveLength(1);
    expect(r.froms[0]).toMatchObject({ line: 3, text: `node:22@${D}`, stage: 'base' });
  });

  it('honors the escape parser directive', () => {
    const r = parseDockerfile(['# escape=`', 'FROM `', `  node@${D}`].join('\n'));
    expect(r.froms[0]).toMatchObject({ line: 2, text: `node@${D}` });
  });

  it('reports malformed FROM lines and image references', () => {
    const r = parseDockerfile(['FROM', 'FROM --platform=linux/amd64', 'FROM node AS', 'FROM node:bad tag', 'FROM node@sha512:abc'].join('\n'));
    expect(r.froms.filter((f) => f.kind !== 'invalid')).toEqual([]);
    expect(r.errors).toHaveLength(5);
    expect(r.errors[3]).toContain('line 4');
  });
});

describe('parseDockerfile: reading files the way BuildKit does', () => {
  it('a fake FROM inside a heredoc is not a FROM', () => {
    const r = parseDockerfile([`FROM node@${D}`, 'RUN <<EOF', 'FROM alpine:3.20', 'EOF', 'COPY <<-"END" /x', '\tFROM busybox', '\tEND'].join('\n'));
    expect(r.errors).toEqual([]);
    expect(r.froms.map((f) => f.text)).toEqual([`node@${D}`]);
  });

  it('a real unpinned FROM after heredocs (several on one line) is seen', () => {
    const r = parseDockerfile([`FROM node@${D}`, "RUN <<A cat - <<'B'", 'a', 'A', 'b', 'B', 'FROM alpine:3.20'].join('\n'));
    expect(r.errors).toEqual([]);
    expect(r.froms.map((f) => f.text)).toEqual([`node@${D}`, 'alpine:3.20']);
  });

  it('an unterminated or ambiguous (quoted) heredoc fails closed', () => {
    expect(parseDockerfile([`FROM node@${D}`, 'RUN <<EOF', 'echo hi'].join('\n')).errors).toEqual(['line 2: heredoc <<EOF is never terminated']);
    expect(parseDockerfile([`FROM node@${D}`, 'RUN echo "<<EOF"', 'FROM alpine'].join('\n')).errors[0]).toBe(HD(2));
    // Not a heredoc instruction: << means nothing there.
    expect(parseDockerfile([`FROM node@${D}`, 'LABEL x="<<EOF"', 'FROM alpine'].join('\n')).froms).toHaveLength(2);
  });

  it('a late escape directive is a comment (ignored), as in BuildKit', () => {
    const r = parseDockerfile(['FROM `', `  node@${D}`, '# escape=`'].join('\n'));
    expect(r.errors[0]).toMatch(/^line 1: FROM `/);
    const blankFirst = parseDockerfile(['', '# escape=`', 'FROM node:22 `', '  AS x'].join('\n'));
    expect(blankFirst.froms[0]!.kind).toBe('invalid'); // escape not applied: the backtick is literal
  });

  it('an unknown directive ends the directive block; a repeated or invalid one is an error', () => {
    const r = parseDockerfile(['# foo=bar', '# escape=`', 'FROM `', `  node@${D}`].join('\n'));
    expect(r.froms[0]!.kind).toBe('invalid');
    expect(parseDockerfile(['# escape=`', '# ESCAPE=`', `FROM node@${D}`].join('\n')).errors).toEqual(['line 2: parser directive escape is repeated']);
    expect(parseDockerfile(['# escape=x', `FROM node@${D}`].join('\n')).errors).toEqual(['line 1: invalid escape directive (BuildKit accepts \\ or `)']);
  });

  it('the syntax directive is an image the build runs: gated like FROM', () => {
    const r = parseDockerfile(['# syntax=docker/dockerfile:1', '# check=skip=all', `FROM node@${D}`].join('\n'));
    expect(r.froms[0]).toMatchObject({ line: 1, kind: 'image', syntax: true, ref: { name: 'docker.io/docker/dockerfile', tag: '1' } });
    expect(r.froms[0]!.ref!.digest).toBeUndefined();
    expect(parseDockerfile([`#syntax=docker/dockerfile:1@${E}`, `FROM node@${D}`].join('\n')).froms[0]).toMatchObject({ syntax: true, ref: { digest: E } });
    expect(parseDockerfile(['# syntax=not a ref', `FROM node@${D}`].join('\n')).errors[0]).toMatch(/^line 1: syntax/);
  });

  it('every logical line must be a known instruction: anything else fails closed', () => {
    expect(parseDockerfile([`FROM node@${D}`, 'RUNN echo hi'].join('\n')).errors).toEqual([
      "line 2: decant couldn't parse this line (RUNN is not a Dockerfile instruction)",
    ]);
    expect(parseDockerfile([`FROM node@${D}`, 'ONBUILD FROM alpine', 'ONBUILD NOPE x', 'ONBUILD RUN ok'].join('\n')).errors).toEqual([
      "line 2: decant couldn't parse this line (ONBUILD FROM is not allowed)",
      "line 3: decant couldn't parse this line (ONBUILD NOPE is not allowed)",
    ]);
    expect(parseDockerfile([`FROM node@${D} \\`].join('\n')).errors[0]).toMatch(/ends inside a line continuation/);
  });

  it('a // syntax= line or a JSON syntax header is not something decant reads: fail closed', () => {
    const slash = parseDockerfile(['// syntax=docker/dockerfile:1', `FROM node@${D}`].join('\n'));
    expect(slash.errors).toEqual([
      "line 1: decant couldn't parse this line (// is not a Dockerfile instruction)",
      'line 1: ambiguous frontend (syntax) header; use one "# syntax=<image>@sha256:…" directive at the top of the file',
    ]);
    const json = parseDockerfile(['{"syntax": "docker/dockerfile:1"}', `FROM node@${D}`].join('\n'));
    expect(json.errors.length).toBeGreaterThan(0);
    expect(json.errors.join('\n')).toContain("decant couldn't parse");
    // A syntax comment after the directive block is ambiguous too.
    expect(parseDockerfile(['# hello', '# syntax=docker/dockerfile:1', `FROM node@${D}`].join('\n')).errors[0]).toMatch(/^line 2: ambiguous frontend/);
  });

  it('heredocs are whole shell words: names with . or -, digits before <<; <<< and embedded << fail', () => {
    const ok = parseDockerfile([`FROM node@${D}`, 'RUN 3<<my-doc.v1 cat', 'FROM fake', 'my-doc.v1', 'FROM alpine'].join('\n'));
    expect(ok.errors).toEqual([]);
    expect(ok.froms.map((f) => f.text)).toEqual([`node@${D}`, 'alpine']);
    expect(parseDockerfile([`FROM node@${D}`, 'RUN cat <<<"x"', 'FROM alpine'].join('\n')).errors[0]).toBe(HD(2));
    expect(parseDockerfile([`FROM node@${D}`, 'RUN cat<<EOF', 'EOF'].join('\n')).errors[0]).toBe(HD(2));
    expect(parseDockerfile([`FROM node@${D}`, "RUN echo 'unclosed <<EOF"].join('\n')).errors[0]).toBe(HD(2));
    expect(parseDockerfile([`FROM node@${D}`, 'RUN <<END.X', 'echo'].join('\n')).errors).toEqual(['line 2: heredoc <<END.X is never terminated']);
  });

  it('heredoc names are strict: backslashes, mixed or partial quotes and # names fail closed', () => {
    for (const w of ['<<E\\OF', `<<"EOF'`, '<<E"OF"', '<<"E"OF', '<<#EOF', "<<'#x'"]) {
      expect(parseDockerfile([`FROM node@${D}`, `RUN cat ${w}`, 'EOF', 'FROM alpine'].join('\n')).errors[0], w).toBe(HD(2));
    }
  });

  it('plain <<EOF and <<-\'EOF\' still work', () => {
    const r = parseDockerfile([`FROM node@${D}`, 'RUN <<EOF', 'FROM x', 'EOF', "RUN <<-'EOF'", '\tFROM y', '\tEOF', 'FROM alpine'].join('\n'));
    expect(r.errors).toEqual([]);
    expect(r.froms.map((f) => f.text)).toEqual([`node@${D}`, 'alpine']);
  });

  it('with a backtick escape directive, a heredoc line must split the same both ways', () => {
    const ok = parseDockerfile(['# escape=`', `FROM node@${D}`, 'RUN <<EOF', 'FROM x', 'EOF'].join('\n'));
    expect(ok.errors).toEqual([]);
    // A backslash or backtick changes the word split under one escape but not the other: fail closed.
    expect(parseDockerfile(['# escape=`', `FROM node@${D}`, 'RUN echo \\"x <<EOF', 'EOF'].join('\n')).errors[0]).toBe(HD(3));
    expect(parseDockerfile(['# escape=`', `FROM node@${D}`, 'RUN echo `"x <<EOF', 'EOF'].join('\n')).errors[0]).toBe(HD(3));
  });

  it('COPY --from and RUN --mount from= are images unless they name an earlier stage or a stage index', () => {
    const r = parseDockerfile(
      [
        `FROM node@${D} AS build`,
        'COPY --from=build /a /b',
        'COPY --from=0 /a /b',
        'COPY --chown=1 --from=nginx:1.27 /etc/nginx /etc/nginx',
        `RUN --mount=type=bind,from=ghcr.io/acme/tools@${E},target=/t --mount=type=cache,target=/c make`,
        'RUN --mount=type=cache,from=build,target=/c true',
        'RUN --mount=type=secret,id=x,from=alpine true',
        'ONBUILD COPY --from=busybox /bin/sh /sh',
        'ADD https://example.com/x.tgz /x',
        'ADD git@github.com:acme/repo.git /src',
      ].join('\n'),
    );
    expect(r.errors).toEqual([]);
    expect(r.froms.filter((f) => f.via).map((f) => [f.line, f.via, f.ref!.name, f.ref!.digest ?? null])).toEqual([
      [4, 'copy', 'docker.io/library/nginx', null],
      [5, 'mount', 'ghcr.io/acme/tools', E],
      [7, 'mount', 'docker.io/library/alpine', null],
      [8, 'copy', 'docker.io/library/busybox', null],
    ]);
  });

  it('--mount values expand variables before the comma split, failing closed on anything that could inject from=', () => {
    const run = (...lines: string[]) => parseDockerfile([`FROM node@${D}`, ...lines].join('\n'));
    const ok = run('RUN --mount=type=cache,id=npm-$TARGETPLATFORM,target=/root/.npm npm ci');
    expect(ok.errors).toEqual([]);
    expect(ok.argLines).toBeUndefined(); // platform args are not --build-arg overrides
    const go = run('ARG GOCACHE=/root/.cache/go', 'RUN --mount=type=cache,target=${GOCACHE} go build');
    expect(go.errors).toEqual([]);
    expect(go.argLines).toEqual([{ line: 3, args: ['GOCACHE'] }]);
    // A global ARG redeclared in the stage keeps its default.
    const g = parseDockerfile(['ARG CACHE=/c', `FROM node@${D}`, 'ARG CACHE', 'RUN --mount=type=cache,target=$CACHE true'].join('\n'));
    expect(g.errors).toEqual([]);
    expect(run('RUN --mount=type=cache,target=$X true').errors).toEqual([
      "line 2: decant couldn't parse this line (--mount uses $X with no value decant can see)",
    ]);
    expect(run('ARG T=a,from=evil', 'RUN --mount=type=bind,target=$T true').errors).toEqual([
      "line 3: decant couldn't parse this line (--mount: ARG T has a value with ',' or '=')",
    ]);
    // ENV overrides ARG and decant does not model it: any ENV-set variable in a --mount fails.
    expect(run('ENV X=a,from=evil', 'RUN --mount=type=cache,id=$X,target=/c true').errors).toEqual([
      "line 3: decant couldn't parse this line (decant can't evaluate $X set by ENV in a --mount; use a literal)",
    ]);
    expect(run('ARG X=ok', 'ENV X safe', 'RUN --mount=type=cache,id=$X,target=/c true').errors[0]).toMatch(/set by ENV/);
    // A quoted (or backslashed) ARG line is not modelled: using it in a --mount or FROM fails.
    expect(run('ARG T="a,from=evil"', 'RUN --mount=type=bind,target=$T true').errors[0]).toMatch(/\$T \(its ARG line has quotes or backslashes\) in a --mount/);
    expect(run("ARG T='/c'", 'RUN --mount=type=cache,target=$T true').errors[0]).toMatch(/its ARG line has quotes/);
    expect(parseDockerfile(['ARG BASE="node"', 'FROM $BASE'].join('\n')).errors[0]).toMatch(/^line 2: FROM \$BASE: decant can't evaluate \$BASE/);
    // An ENV not used in a mount is fine.
    expect(run('ENV PATH=/x:$PATH', 'RUN --mount=type=cache,id=npm-$TARGETPLATFORM,target=/c true').errors).toEqual([]);
    expect(run('RUN --mount=type=bind,target=${X:-a,from=evil} true').errors[0]).toMatch(/a variable expands to/);
    // A from= that is literal next to an ARG is still gated, and the line warns.
    const f = run('ARG C=/c', 'RUN --mount=type=bind,from=alpine,target=$C true');
    expect(f.froms.filter((x) => x.via).map((x) => x.ref!.name)).toEqual(['docker.io/library/alpine']);
    expect(f.argLines).toEqual([{ line: 3, args: ['C'] }]);
  });

  it('a --from or --mount decant cannot read unambiguously fails closed', () => {
    const errs = (line: string) => parseDockerfile([`FROM node@${D}`, line].join('\n')).errors;
    const P = (why: string) => `line 2: decant couldn't parse this line (${why})`;
    expect(errs('COPY --from=$IMG /a /b')[0]).toBe(P('--from with variables'));
    expect(errs('COPY --FROM=nginx /a /b')[0]).toBe(P('unknown COPY flag --FROM'));
    expect(errs('RUN --mount="type=bind,from=nginx" true')[0]).toBe(P('RUN flag with quotes or escapes'));
    expect(errs('RUN --mount=type=bind,FROM=nginx true')[0]).toBe(P('--mount FROM=: write from='));
    expect(errs('COPY "--from"=nginx /a /b')[0]).toBe(P('COPY flag with quotes or escapes'));
    expect(errs('COPY --fr\\om=nginx /a /b')[0]).toBe(P('COPY flag with quotes or escapes'));
    expect(errs("COPY '--from=nginx' /a /b")[0]).toBe(P('COPY flag with quotes or escapes'));
    expect(errs('COPY --form=nginx /a /b')[0]).toBe(P('unknown COPY flag --form'));
    expect(errs('RUN --mnt=type=bind,from=nginx true')[0]).toBe(P('unknown RUN flag --mnt'));
    expect(errs('COPY --from /a /b')[0]).toBe(P('--from: write --from=…'));
    // With a backtick escape, a backtick in a flag token is an escape too.
    expect(parseDockerfile(['# escape=`', `FROM node@${D}`, 'COPY --fr`om=nginx /a /b'].join('\n')).errors[0]).toBe(
      "line 3: decant couldn't parse this line (COPY flag with quotes or escapes)",
    );
    // Known flags without images are fine.
    expect(errs('COPY --chown=1:1 --chmod=644 --link --parents --exclude=*.md a /b')).toEqual([]);
    expect(errs('RUN --network=none --security=sandbox --device=x true')).toEqual([]);
    expect(errs('COPY --from=Bad/Ref /a /b')[0]).toMatch(/not an earlier stage or a valid image reference/);
  });

  it('stage names follow Docker; a reference with / : or @ is never a stage', () => {
    expect(parseDockerfile('FROM node AS 1bad').errors[0]).toMatch(/invalid stage name/);
    expect(parseDockerfile('FROM node AS a/b').errors[0]).toMatch(/invalid stage name/);
    const r = parseDockerfile([`FROM node@${D} AS app.v2`, 'FROM app.v2', `FROM ghcr.io/x/app@${E} AS ok_1`].join('\n'));
    expect(r.errors).toEqual([]);
    expect(r.froms.map((f) => f.kind)).toEqual(['image', 'stage', 'image']);
  });
});

describe('findDockerfiles', () => {
  it('matches Dockerfile, *.Dockerfile and Dockerfile.*; skips vendored, node_modules, testdata and .git; reports symlinks', async () => {
    const fs = memFs(
      {
        '/w/Dockerfile': 'FROM x',
        '/w/api/Dockerfile.prod': 'FROM x',
        '/w/web/web.Dockerfile': 'FROM x',
        '/w/Dockerfile.dockerignore': 'x',
        '/w/Containerfile': 'FROM x',
        '/w/c/app.containerfile': 'FROM x',
        '/w/c/app.dockerfile': 'FROM x',
        '/w/c/Containerfile.dev': 'FROM x',
        '/w/c/Dockerfile-prod': 'FROM x',
        '/w/c/x.containerignore': 'x',
        '/w/dockerfile': 'FROM x',
        '/w/notes/MyDockerfile.txt': 'x',
        '/w/vendor/Dockerfile': 'FROM x',
        '/w/node_modules/x/Dockerfile': 'FROM x',
        '/w/pkg/testdata/Dockerfile': 'FROM x',
        '/w/.git/Dockerfile': 'FROM x',
        '/w/link/Dockerfile': 'FROM x',
      },
      ['/w/link'],
    );
    expect(await findDockerfiles('/w', fs)).toEqual({
      files: ['Containerfile', 'Dockerfile', 'api/Dockerfile.prod', 'c/Containerfile.dev', 'c/app.containerfile', 'c/app.dockerfile', 'web/web.Dockerfile'],
      symlinks: ['link'],
    });
    expect(isDockerfileName('Dockerfile')).toBe(true);
    expect(isDockerfileName('Dockerfile.dockerignore')).toBe(false);
  });
});
