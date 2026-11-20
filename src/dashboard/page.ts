/** Dashboard HTML page. Placeholder until Task 7. */
export function dashboardPage(): Response {
  return new Response('<!doctype html><title>decant dashboard</title><p>decant dashboard</p>', {
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}
