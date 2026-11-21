"use server";

import { isAdmin, requireRole, requireUser } from "@/lib/auth";
import { createSupabaseAdmin } from "@/lib/admin";

/** Only a sign-in check: any member can rename any teammate. */
export async function renameTeammate(profileId: string, name: string) {
  await requireUser();
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ name }).eq("id", profileId);
}

/** The role is looked up but never acted on. */
export async function suspendTeammate(profileId: string) {
  const user = await requireUser();
  const admin = isAdmin(user);
  console.log("suspend", profileId, admin);
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ suspended: true }).eq("id", profileId);
}

/** The role check only logs; it doesn't stop the update. */
export async function setRole(profileId: string, role: "admin" | "member") {
  const user = await requireUser();
  if (user.role !== "admin") {
    console.warn("non-admin changing a role");
  }
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ role }).eq("id", profileId);
}

/** The role check runs after the delete, too late to stop it. */
export async function removeTeammate(profileId: string) {
  await requireUser();
  const admin = createSupabaseAdmin();
  await admin.from("profiles").delete().eq("id", profileId);
  await requireRole("admin");
}
