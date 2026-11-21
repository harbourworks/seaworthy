import { checkRateLimit } from "./limits";

const apiRateLimit = { limit: 5, windowSeconds: 3600 };

export async function guard(key: string): Promise<boolean> {
  return checkRateLimit(`invite:${key}`, apiRateLimit.limit, apiRateLimit.windowSeconds);
}
