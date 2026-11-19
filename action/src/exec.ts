import { spawn } from 'node:child_process';

export type Exec = (
  cmd: string,
  args: string[],
  opts?: { cwd?: string; env?: Record<string, string>; input?: string },
) => Promise<{ code: number; stdout: string; stderr: string }>;

const SECRET_NAME = /TOKEN|SECRET|KEY|PASSWORD/i;

/**
 * The environment child processes inherit: drops action inputs (INPUT_*, which carry tokens), the
 * runner's ACTIONS_* runtime credentials, and any variable whose name mentions TOKEN, SECRET, KEY or
 * PASSWORD. Child processes include GuardDog analysing untrusted tarballs, so nothing secret is
 * inherited; a caller that needs one passes it in opts.env explicitly.
 */
export function scrubEnv(env: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) continue;
    if (k.startsWith('INPUT_') || k.startsWith('ACTIONS_') || SECRET_NAME.test(k)) continue;
    out[k] = v;
  }
  return out;
}

/** Default Exec: child_process.spawn, no shell, scrubbed environment plus opts.env. */
export const defaultExec: Exec = (cmd, args, opts = {}) =>
  new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: { ...scrubEnv(process.env), ...opts.env },
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (d: string) => (stdout += d));
    child.stderr.setEncoding('utf8').on('data', (d: string) => (stderr += d));
    child.on('error', (e) => resolve({ code: 127, stdout, stderr: stderr + String(e.message) }));
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
    child.stdin.on('error', () => {});
    child.stdin.end(opts.input ?? '');
  });
