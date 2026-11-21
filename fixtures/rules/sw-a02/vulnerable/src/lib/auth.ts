import { getSession } from "./session";

export type Role = "owner" | "admin" | "manager" | "member";

/** The signed-in user, or a thrown error. Says nothing about their role. */
export async function requireUser() {
  const session = await getSession();
  if (!session) throw new Error("unauthorised");
  return session;
}

/** Throws unless the signed-in user has one of the roles. */
export async function requireRole(...roles: Role[]) {
  const session = await requireUser();
  if (!roles.includes(session.role)) throw new Error("forbidden");
  return session;
}

export async function requireAdmin() {
  return requireRole("owner", "admin");
}

export async function assertPermission(permission: string) {
  const session = await requireUser();
  if (!session.permissions.includes(permission)) throw new Error("forbidden");
  return session;
}

export function isAdmin(user: { role: Role }) {
  return user.role === "owner" || user.role === "admin";
}

export function hasRole(user: { role: Role }, role: Role) {
  return user.role === role;
}
