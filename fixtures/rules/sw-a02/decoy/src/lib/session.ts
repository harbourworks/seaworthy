import type { Role } from "./auth";

export async function getSession(): Promise<{ id: string; role: Role; permissions: string[] } | null> {
  // A real app reads the session cookie here.
  return null;
}
