import { appendFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

type Env = Record<string, string | undefined>;

export function getInput(name: string, env: Env = process.env): string {
  // The Actions runner keeps hyphens (INPUT_DECANT-URL), like @actions/core; the underscore form is a fallback.
  const key = name.replace(/ /g, '_').toUpperCase();
  return (env[`INPUT_${key}`] ?? env[`INPUT_${key.replace(/-/g, '_')}`] ?? '').trim();
}

function escapeData(s: string): string {
  return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProp(s: string): string {
  return escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function command(level: string, msg: string, file?: string): void {
  const props = file ? ` file=${escapeProp(file)}` : '';
  process.stdout.write(`::${level}${props}::${escapeData(msg)}\n`);
}

export function mask(v: string): void {
  if (v) command('add-mask', v);
}
export const notice = (msg: string, file?: string): void => command('notice', msg, file);
export const warning = (msg: string, file?: string): void => command('warning', msg, file);
export const error = (msg: string, file?: string): void => command('error', msg, file);

function appendTo(envName: string, text: string, env: Env): void {
  const path = env[envName];
  if (path) appendFileSync(path, text);
}

function keyValue(k: string, v: string): string {
  const delim = `ghadelim_${randomUUID()}`;
  return `${k}<<${delim}\n${v}\n${delim}\n`;
}

export function setOutput(k: string, v: string, env: Env = process.env): void {
  appendTo('GITHUB_OUTPUT', keyValue(k, v), env);
}

export function appendSummary(md: string, env: Env = process.env): void {
  appendTo('GITHUB_STEP_SUMMARY', `${md}\n`, env);
}

export function exportVar(k: string, v: string, env: Env = process.env): void {
  appendTo('GITHUB_ENV', keyValue(k, v), env);
}
