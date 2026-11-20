import { describe, expect, it } from 'vitest';
import { DASHBOARD_HTML, dashboardPage } from '../src/dashboard/page';

const CSP =
  "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'";

describe('dashboard page', () => {
  it('is served as no-store text/html with the exact CSP', async () => {
    const res = dashboardPage();
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('content-security-policy')).toBe(CSP);
    expect(await res.text()).toBe(DASHBOARD_HTML);
  });

  it('makes no external requests', () => {
    expect(DASHBOARD_HTML).not.toMatch(/https?:\/\//);
    expect(DASHBOARD_HTML).not.toMatch(/<script[^>]*\ssrc/i);
    expect(DASHBOARD_HTML).not.toMatch(/<link\b/i);
    expect(DASHBOARD_HTML).not.toMatch(/@import|\burl\(/i);
  });

  it('contains every section heading', () => {
    for (const h of ['Needs attention', 'Activity', 'Security', 'Freshness', 'Uptime', 'Policy', 'Packages', 'Recently resolved']) {
      expect(DASHBOARD_HTML).toMatch(new RegExp(`<h2[^>]*>${h}`));
    }
    expect(DASHBOARD_HTML).toMatch(/<h1[^>]*>decant<\/h1>/);
  });

  it('never parses data as HTML', () => {
    expect(DASHBOARD_HTML).not.toContain('innerHTML');
    expect(DASHBOARD_HTML).not.toContain('outerHTML');
    expect(DASHBOARD_HTML).not.toContain('insertAdjacentHTML');
    expect(DASHBOARD_HTML).not.toContain('document.write');
  });

  it('has labelled, accessible controls and a dark palette', () => {
    expect(DASHBOARD_HTML).toMatch(/<label[^>]*for="project"/);
    expect(DASHBOARD_HTML).toMatch(/<label[^>]*for="q"/);
    for (const r of ['7', '30', '90']) expect(DASHBOARD_HTML).toMatch(new RegExp(`<button[^>]*data-range="${r}"[^>]*aria-pressed`));
    expect(DASHBOARD_HTML).toContain('prefers-color-scheme: dark');
  });
});
