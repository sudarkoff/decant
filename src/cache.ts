/**
 * A small per-isolate cache with a per-entry expiry and a size cap (oldest insertion evicted first).
 * Times are the caller's clock in ms. An entry also expires if the clock reads earlier than when it was
 * set, so a clock step backwards can never stretch an entry's life past its TTL.
 */
export class TtlCache<V> {
  private readonly m = new Map<string, { v: V; at: number; exp: number }>();

  constructor(private readonly max: number) {}

  get(key: string, now: number): V | undefined {
    const e = this.m.get(key);
    if (!e) return undefined;
    if (now >= e.exp || now < e.at) {
      this.m.delete(key);
      return undefined;
    }
    return e.v;
  }

  set(key: string, v: V, now: number, ttlMs: number): void {
    this.m.delete(key);
    this.m.set(key, { v, at: now, exp: now + ttlMs });
    if (this.m.size > this.max) this.m.delete(this.m.keys().next().value!);
  }

  delete(key: string): void {
    this.m.delete(key);
  }

  clear(): void {
    this.m.clear();
  }
}
