/** Reads the whole stream, or cancels it and returns null once it exceeds `max` bytes. */
export async function readUpTo(reader: ReadableStreamDefaultReader<Uint8Array>, max: number): Promise<Uint8Array | null> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/** Feeds every chunk to all sinks, then closes them. */
export async function pump(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  sinks: WritableStreamDefaultWriter<Uint8Array>[],
): Promise<void> {
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    await Promise.all(sinks.map((w) => w.write(value)));
  }
  await Promise.all(sinks.map((w) => w.close()));
}
