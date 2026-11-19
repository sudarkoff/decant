/** Shared fetch plumbing for the action's clients: timeouts and secret-free error messages. */

export const TIMEOUT_MS = 30_000;
export const OSV_TIMEOUT_MS = 10_000;

/** Replaces every non-empty secret in `s` with ***. Callers pass derived forms (e.g. Basic base64) too. */
export function redact(s: string, secrets: string[]): string {
  let out = s;
  for (const sec of secrets) {
    if (!sec) continue;
    out = out.split(sec).join('***');
  }
  return out;
}

export type RequestOpts = { label: string; timeoutMs: number; secrets?: string[] };

/**
 * fetch with an AbortSignal timeout. Network errors and timeouts become an Error whose message
 * names `label` and the reason, with secrets removed. Never includes request headers.
 */
export async function request(f: typeof fetch, url: string, init: RequestInit, o: RequestOpts): Promise<Response> {
  try {
    return await f(url, { ...init, signal: AbortSignal.timeout(o.timeoutMs) });
  } catch (e) {
    const name = (e as Error)?.name;
    const why = name === 'TimeoutError' || name === 'AbortError' ? `timed out after ${o.timeoutMs / 1000}s` : String((e as Error)?.message ?? e);
    throw new Error(redact(`${o.label}: ${why}`, o.secrets ?? []));
  }
}

/** An Error for a non-OK response: label, status and the start of the body, secrets removed. */
export async function httpError(res: Response, o: Pick<RequestOpts, 'label' | 'secrets'>): Promise<Error> {
  let text = '';
  try {
    text = (await res.text()).slice(0, 300).replace(/\s+/g, ' ').trim();
  } catch {
    // body unreadable: status alone
  }
  return new Error(redact(`${o.label}: HTTP ${res.status}${text ? ` ${text}` : ''}`, o.secrets ?? []));
}

/** Reads JSON, turning a parse failure into a labelled Error. */
export async function readJson<T>(res: Response, label: string): Promise<T> {
  try {
    return (await res.json()) as T;
  } catch {
    throw new Error(`${label}: invalid JSON response`);
  }
}
