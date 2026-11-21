const hits = new Map<string, { count: number; resetAt: number }>();
export function isRateLimited(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = hits.get(key);
  if (!entry || entry.resetAt < now) { hits.set(key, { count: 1, resetAt: now + windowMs }); return false; }
  entry.count += 1;
  return entry.count > limit;
}
