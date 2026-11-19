/** Go module proxy case encoding: each uppercase letter becomes '!' + its lowercase. */
export function escapeModulePath(p: string): string {
  return p.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

/** Inverse of escapeModulePath. Null when the input has uppercase or a '!' not followed by a-z. */
export function unescapeModulePath(p: string): string | null {
  let out = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i]!;
    if (c >= 'A' && c <= 'Z') return null;
    if (c !== '!') {
      out += c;
      continue;
    }
    const n = p[++i];
    if (n === undefined || n < 'a' || n > 'z') return null;
    out += n.toUpperCase();
  }
  return out;
}
