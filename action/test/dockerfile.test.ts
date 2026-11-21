import { describe, expect, it } from 'vitest';
import { findDockerfiles, isDockerfileName, parseDockerfile, parseImageRef } from '../src/dockerfile';
import { memFs } from './fakes';

const D = `sha256:${'a'.repeat(64)}`;
const E = `sha256:${'b'.repeat(64)}`;

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
        '# syntax=docker/dockerfile:1',
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

describe('findDockerfiles', () => {
  it('matches Dockerfile, *.Dockerfile and Dockerfile.*; skips vendored, node_modules, testdata and .git; reports symlinks', async () => {
    const fs = memFs(
      {
        '/w/Dockerfile': 'FROM x',
        '/w/api/Dockerfile.prod': 'FROM x',
        '/w/web/web.Dockerfile': 'FROM x',
        '/w/Dockerfile.dockerignore': 'x',
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
    expect(await findDockerfiles('/w', fs)).toEqual({ files: ['Dockerfile', 'api/Dockerfile.prod', 'web/web.Dockerfile'], symlinks: ['link'] });
    expect(isDockerfileName('Dockerfile')).toBe(true);
    expect(isDockerfileName('Dockerfile.dockerignore')).toBe(false);
  });
});
