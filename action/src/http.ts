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
    throw new Error(redact(`${o.label}: ${failure(e, o.timeoutMs)}`, o.secrets ?? []));
  }
}

const isTimeout = (e: unknown) => ['TimeoutError', 'AbortError'].includes((e as Error)?.name);

/**
 * Why a fetch threw. undici says only "fetch failed" and puts the reason in `cause` (a code such as
 * ECONNRESET or UND_ERR_SOCKET, and a message such as "other side closed"), so the cause is appended.
 */
function failure(e: unknown, timeoutMs: number): string {
  if (isTimeout(e)) return `timed out after ${timeoutMs / 1000}s`;
  const msg = String((e as Error)?.message ?? e);
  const cause = (e as { cause?: { code?: unknown; message?: unknown } })?.cause;
  const code = typeof cause?.code === 'string' ? cause.code : '';
  const cmsg = typeof cause?.message === 'string' ? cause.message : '';
  const why = code && cmsg && !cmsg.includes(code) ? `${code}: ${cmsg}` : code || cmsg;
  return why && !msg.includes(why) ? `${msg} (${why})` : msg;
}

export type RetryOpts = RequestOpts & {
  /** Waits between attempts; injected by tests. */
  sleep: (ms: number) => Promise<void>;
  /** [0, 1); jitters each delay to 75–125% of its base. */
  random?: () => number;
};

export const RETRY_DELAYS_MS = [500, 1000, 2000];
const RETRY_STATUSES = new Set([502, 503, 504]);

export const realSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * `request`, retried for connection-level failures: a fetch that throws (reset, socket closed, timeout)
 * or a 502/503/504 from a proxy in front of the server. Up to RETRY_DELAYS_MS.length + 1 attempts with
 * jittered backoff. Only for idempotent requests. A 4xx or other status is returned at once; a 502–504
 * that persists is returned as the last response; a throw that persists names the cause and the count.
 */
export async function requestWithRetry(f: typeof fetch, url: string, init: RequestInit, o: RetryOpts): Promise<Response> {
  const attempts = RETRY_DELAYS_MS.length + 1;
  const random = o.random ?? Math.random;
  for (let i = 0; ; i++) {
    const last = i === attempts - 1;
    let res: Response;
    try {
      res = await f(url, { ...init, signal: AbortSignal.timeout(o.timeoutMs) });
    } catch (e) {
      if (last) {
        const why = isTimeout(e) ? `timed out (${o.timeoutMs / 1000}s)` : failure(e, o.timeoutMs);
        throw new Error(redact(`${o.label}: ${why} after ${attempts} attempts`, o.secrets ?? []));
      }
      await o.sleep(Math.round(RETRY_DELAYS_MS[i]! * (0.75 + 0.5 * random())));
      continue;
    }
    if (last || !RETRY_STATUSES.has(res.status)) return res;
    await res.body?.cancel().catch(() => {});
    await o.sleep(Math.round(RETRY_DELAYS_MS[i]! * (0.75 + 0.5 * random())));
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
