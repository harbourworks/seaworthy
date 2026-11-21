"use server";

import { isAdmin, requireRole, requireUser } from "@/lib/auth";
import { createSupabaseAdmin } from "@/lib/admin";

/** Members may only rename themselves. */
export async function renameTeammate(profileId: string, name: string) {
  const user = await requireUser();
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ name }).eq("id", profileId).eq("user_id", user.id);
}

/** The role check stops non-admins before the update. */
export async function suspendTeammate(profileId: string) {
  const user = await requireUser();
  if (!isAdmin(user)) return { ok: false };
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ suspended: true }).eq("id", profileId);
  return { ok: true };
}

export async function setRole(profileId: string, role: "admin" | "member") {
  const user = await requireUser();
  if (user.role !== "admin") {
    throw new Error("forbidden");
  }
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ role }).eq("id", profileId);
}

/** The role check runs first. */
export async function removeTeammate(profileId: string) {
  await requireRole("admin");
  const admin = createSupabaseAdmin();
  await admin.from("profiles").delete().eq("id", profileId);
}
