import { hashToken, newToken, type AuthCtx } from '../auth';
import { json } from '../http';
import { verifyAdvisoryFix } from '../osv';
import { parsePolicy, type Policy } from '../policy/schema';
import { globalBlockStmt } from '../policy/store';
import { formatPackageId, parsePackageId, type Deps, type Env, type PackageRef } from '../types';

const MAX_BODY = 1024 * 1024;
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const REF_RE = /^[A-Za-z0-9._-]{1,64}$/;
const SCANNER_RE = /^[A-Za-z0-9._-]{1,64}$/;
const RESULTS = new Set(['clean', 'flagged', 'malicious']);

const NO_STORE = { 'cache-control': 'no-store' };
const reply = (body: unknown, status = 200) => json(body, status, NO_STORE);
const err = (status: number, error: string, extra: Record<string, unknown> = {}) => reply({ error, ...extra }, status);
const forbidden = () => err(403, 'forbidden');
const notFound = () => err(404, 'not found');
const methodNotAllowed = () => err(405, 'method not allowed');

class HttpError extends Error {
  constructor(readonly res: Response) {
    super('http error');
  }
}

/** Reads at most MAX_BODY bytes and parses a JSON object. Throws HttpError(400/413). */
async function readJsonObject(req: Request): Promise<Record<string, unknown>> {
  const declared = Number(req.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY) throw new HttpError(err(413, 'body too large'));
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (req.body) {
    const reader = req.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY) {
        await reader.cancel();
        throw new HttpError(err(413, 'body too large'));
      }
      chunks.push(value);
    }
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(buf));
  } catch {
    throw new HttpError(err(400, 'body must be JSON'));
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(err(400, 'body must be a JSON object'));
  }
  return parsed as Record<string, unknown>;
}

const isOperator = (a: AuthCtx) => a.kind === 'operator';
const isCi = (a: AuthCtx): a is { kind: 'ci'; projectId: string } => a.kind === 'ci';
const isOwnCi = (a: AuthCtx, projectId: string) => isCi(a) && a.projectId === projectId;

export async function handleAdmin(
  req: Request,
  env: Env,
  deps: Deps,
  _ctx: ExecutionContext,
  auth: AuthCtx,
  path: string,
): Promise<Response> {
  // Read tokens never touch the admin API, whatever the route.
  if (auth.kind === 'read') return forbidden();
  try {
    return await route(req, env, deps, auth, path);
  } catch (e) {
    if (e instanceof HttpError) return e.res;
    throw e;
  }
}

async function route(req: Request, env: Env, deps: Deps, auth: AuthCtx, path: string): Promise<Response> {
  const segs = path.replace(/^\/api\/?/, '').split('/').filter((s, i, a) => s !== '' || i < a.length - 1);
  const m = req.method;

  if (segs.length === 1 && segs[0] === 'projects') {
    if (m !== 'POST') return methodNotAllowed();
    if (!isOperator(auth)) return forbidden();
    return createProject(req, env, deps);
  }
  if (segs.length === 1 && segs[0] === 'verdicts') {
    if (m !== 'PUT' && m !== 'GET') return methodNotAllowed();
    if (!isCi(auth)) return forbidden();
    return m === 'PUT' ? putVerdict(req, env, deps) : getVerdicts(req, env);
  }
  if (segs.length === 3 && segs[0] === 'projects') {
    const id = segs[1]!;
    switch (segs[2]) {
      case 'tokens':
        if (m !== 'POST') return methodNotAllowed();
        if (!isOperator(auth)) return forbidden();
        return createToken(req, env, deps, id);
      case 'policy':
        if (m !== 'PUT') return methodNotAllowed();
        if (!isOwnCi(auth, id)) return forbidden();
        return syncPolicy(req, env, deps, id);
      case 'status':
        if (m !== 'GET') return methodNotAllowed();
        if (!isOwnCi(auth, id)) return forbidden();
        return status(env, id);
    }
  }
  return notFound();
}

async function createProject(req: Request, env: Env, deps: Deps): Promise<Response> {
  const body = await readJsonObject(req);
  if (typeof body.id !== 'string' || !ID_RE.test(body.id)) return err(400, 'id must match ' + ID_RE.source);
  const r = await env.DB.prepare('INSERT OR IGNORE INTO projects (id, created_at) VALUES (?, ?)')
    .bind(body.id, deps.now().toISOString())
    .run();
  if (r.meta.changes === 0) return err(409, 'project exists');
  return reply({ id: body.id }, 201);
}

async function createToken(req: Request, env: Env, deps: Deps, projectId: string): Promise<Response> {
  const body = await readJsonObject(req);
  if (body.kind !== 'read' && body.kind !== 'ci') return err(400, "kind must be 'read' or 'ci'");
  const exists = await env.DB.prepare('SELECT 1 AS x FROM projects WHERE id = ?').bind(projectId).first();
  if (!exists) return notFound();
  const token = newToken(body.kind);
  await env.DB.prepare('INSERT INTO tokens (hash, project_id, kind, created_at) VALUES (?, ?, ?, ?)')
    .bind(await hashToken(token), projectId, body.kind, deps.now().toISOString())
    .run();
  return reply({ token }, 201);
}

function sameAutoShip(a: Policy['autoShip'], b: Policy['autoShip']): boolean {
  return (Object.keys(a) as (keyof Policy['autoShip'])[]).every((k) => a[k] === b[k]);
}

async function syncPolicy(req: Request, env: Env, deps: Deps, projectId: string): Promise<Response> {
  const body = await readJsonObject(req);
  if (typeof body.sha !== 'string' || body.sha === '' || body.sha.length > 100) return err(400, 'sha must be a non-empty string');
  if (typeof body.ref !== 'string' || !REF_RE.test(body.ref)) return err(400, 'ref must match ' + REF_RE.source);
  const { sha, ref } = body as { sha: string; ref: string };

  const parsed = parsePolicy(body.policy);
  if (!parsed.ok) return err(422, 'invalid policy', { errors: parsed.errors });
  const policy = parsed.policy;
  if (policy.project !== projectId) return err(422, `policy.project must be ${projectId}`);

  const seen = new Set<string>();
  for (const a of policy.allow) {
    if (seen.has(a.package)) return err(422, `duplicate allow entry ${a.package}`);
    seen.add(a.package);
  }

  const project = await env.DB.prepare('SELECT main_ref FROM projects WHERE id = ?').bind(projectId).first<{ main_ref: string }>();
  if (!project) return notFound();
  const isMain = ref === project.main_ref;

  if (!isMain) {
    const main = await env.DB.prepare('SELECT json FROM policies WHERE project_id = ? AND ref = ?')
      .bind(projectId, project.main_ref)
      .first<{ json: string }>();
    if (!main) return err(409, 'sync main first');
    const mp = JSON.parse(main.json) as Policy;
    const overlayBlocks = new Set(policy.block.map((b) => b.package));
    if (
      policy.cooldownDays !== mp.cooldownDays ||
      !sameAutoShip(policy.autoShip, mp.autoShip) ||
      mp.block.some((b) => !overlayBlocks.has(b.package))
    ) {
      return err(422, 'overlay may only add allow entries');
    }
  }

  // Verify every advisory allow before writing anything.
  const advisories = policy.allow.filter((a) => a.advisory !== undefined);
  const checks = await Promise.all(
    advisories.map((a) => verifyAdvisoryFix(deps, a.advisory!, parsePackageId(a.package)!)),
  );
  if (checks.includes('unavailable')) return err(503, 'OSV unavailable; retry the sync');
  const bad = advisories.map((a, i) => ({ a, r: checks[i] })).filter((x) => x.r !== 'verified');
  if (bad.length > 0) {
    const entries = bad.map((x) => `${x.a.package} (${x.a.advisory}: ${x.r})`);
    return err(422, `advisory not verified: ${entries.join(', ')}`, { entries });
  }

  const now = deps.now().toISOString();
  const db = env.DB;
  const stmts: D1PreparedStatement[] = [
    db.prepare(
      `INSERT INTO policies (project_id, ref, json, sha, synced_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (project_id, ref) DO UPDATE SET json = excluded.json, sha = excluded.sha, synced_at = excluded.synced_at`,
    ).bind(projectId, ref, JSON.stringify(policy), sha, now),
    db.prepare('DELETE FROM allows WHERE project_id = ? AND ref = ?').bind(projectId, ref),
  ];
  for (const a of policy.allow) {
    const p = parsePackageId(a.package)!;
    stmts.push(
      db.prepare(
        'INSERT INTO allows (project_id, ref, eco, name, version, advisory, reason, verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ).bind(projectId, ref, p.eco, p.name, p.version, a.advisory ?? null, a.reason, a.advisory ? now : null),
    );
  }
  if (isMain) {
    const source = `policy:${projectId}`;
    stmts.push(db.prepare('DELETE FROM global_blocks WHERE source = ?').bind(source));
    for (const b of policy.block) {
      stmts.push(globalBlockStmt(env, parsePackageId(b.package)!, source, b.reason, deps.now()));
    }
  }
  await db.batch(stmts);
  return reply({ ref, allows: policy.allow.length, blocks: policy.block.length });
}

async function putVerdict(req: Request, env: Env, deps: Deps): Promise<Response> {
  const body = await readJsonObject(req);
  const ref = typeof body.package === 'string' ? parsePackageId(body.package) : null;
  if (!ref) return err(400, 'package must be a package ID like npm:name@1.0.0');
  if (typeof body.scanner !== 'string' || !SCANNER_RE.test(body.scanner)) return err(400, 'scanner must match ' + SCANNER_RE.source);
  if (typeof body.scannerVersion !== 'string' || body.scannerVersion === '' || body.scannerVersion.length > 100) {
    return err(400, 'scannerVersion must be a non-empty string');
  }
  if (typeof body.result !== 'string' || !RESULTS.has(body.result)) return err(400, 'result must be clean, flagged or malicious');
  const { scanner, scannerVersion, result } = body as { scanner: string; scannerVersion: string; result: string };
  const details = body.details === undefined ? null : JSON.stringify(body.details);
  const now = deps.now();

  const stmts: D1PreparedStatement[] = [
    env.DB.prepare(
      `INSERT INTO verdicts (eco, name, version, scanner, scanner_version, result, details, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (eco, name, version, scanner) DO UPDATE SET
         scanner_version = excluded.scanner_version, result = excluded.result, details = excluded.details, scanned_at = excluded.scanned_at`,
    ).bind(ref.eco, ref.name, ref.version, scanner, scannerVersion, result, details, now.toISOString()),
  ];
  if (result === 'malicious') {
    stmts.push(globalBlockStmt(env, ref, `verdict:${scanner}`, `malicious verdict from ${scanner} ${scannerVersion}`, now));
  }
  await env.DB.batch(stmts);
  return new Response(null, { status: 204, headers: NO_STORE });
}

async function getVerdicts(req: Request, env: Env): Promise<Response> {
  const id = new URL(req.url).searchParams.get('package');
  const ref: PackageRef | null = id ? parsePackageId(id) : null;
  if (!ref) return err(400, 'package query parameter must be a package ID');
  const r = await env.DB.prepare(
    `SELECT scanner, scanner_version, result, details, scanned_at FROM verdicts
     WHERE eco = ? AND name = ? AND version = ? ORDER BY scanner`,
  )
    .bind(ref.eco, ref.name, ref.version)
    .all<{ scanner: string; scanner_version: string; result: string; details: string | null; scanned_at: string }>();
  const pkg = formatPackageId(ref);
  return reply({
    verdicts: r.results.map((v) => ({
      package: pkg,
      scanner: v.scanner,
      scannerVersion: v.scanner_version,
      result: v.result,
      ...(v.details !== null ? { details: JSON.parse(v.details) } : {}),
      scannedAt: v.scanned_at,
    })),
  });
}

async function status(env: Env, projectId: string): Promise<Response> {
  const [proj, pols, blocks] = await env.DB.batch<Record<string, unknown>>([
    env.DB.prepare('SELECT main_ref FROM projects WHERE id = ?').bind(projectId),
    env.DB.prepare('SELECT ref, sha, synced_at FROM policies WHERE project_id = ? ORDER BY ref').bind(projectId),
    env.DB.prepare('SELECT COUNT(*) AS n FROM global_blocks'),
  ]);
  const p = proj!.results[0] as { main_ref: string } | undefined;
  if (!p) return notFound();
  const rows = pols!.results as { ref: string; sha: string; synced_at: string }[];
  const main = rows.find((r) => r.ref === p.main_ref);
  return reply({
    mainSha: main?.sha ?? null,
    syncedAt: main?.synced_at ?? null,
    overlays: rows.filter((r) => r.ref !== p.main_ref).map((r) => ({ ref: r.ref, syncedAt: r.synced_at })),
    globalBlocks: (blocks!.results[0] as { n: number }).n,
  });
}
