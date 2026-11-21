"use server";

import { redirect } from "next/navigation";
import { assertPermission, hasRole, isAdmin, requireAdmin, requireRole, requireUser } from "@/lib/auth";
import { createSupabaseAdmin } from "@/lib/admin";

/** Admin adds a teammate. The profile ID comes from the user we just created. */
export async function addTeammate(email: string, password: string) {
  await requireRole("admin");
  const admin = createSupabaseAdmin();
  const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
  if (error) return { ok: false };
  await admin.from("profiles").update({ role: "member" }).eq("id", created.user.id);
  return { ok: true };
}

/** Only admins may change another teammate's role. */
export async function setRole(profileId: string, role: "admin" | "member") {
  await requireRole("admin");
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ role }).eq("id", profileId);
  return { ok: true };
}

/** Any signed-in user can start a project; the settings row is keyed by the project just inserted. */
export async function createProject(name: string) {
  const user = await requireUser();
  const admin = createSupabaseAdmin();
  const { data: project } = await admin.from("projects").insert({ name, owner: user.id }).select().single();
  await admin.from("project_settings").update({ name }).eq("project_id", project!.id);
  return project;
}

/** The invited user's ID comes back from Supabase, not from the form. */
export async function inviteTeammate(formData: FormData) {
  const session = await requireAdmin();
  const admin = createSupabaseAdmin();
  const result = await admin.auth.admin.inviteUserByEmail(String(formData.get("email")));
  if (result.error) return { ok: false };
  await admin.from("profiles").update({ invited_by: session.id }).eq("id", result.data.user.id);
  return { ok: true };
}

export async function removeTeammate(profileId: string) {
  await assertPermission("members:write");
  const admin = createSupabaseAdmin();
  await admin.from("profiles").delete().eq("id", profileId);
}

export async function suspendTeammate(profileId: string) {
  const user = await requireUser();
  if (!isAdmin(user)) throw new Error("forbidden");
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ suspended: true }).eq("id", profileId);
}

export async function renameTeammate(profileId: string, name: string) {
  const user = await requireUser();
  if (!hasRole(user, "manager")) {
    redirect("/team");
  }
  const admin = createSupabaseAdmin();
  await admin.from("profiles").update({ name }).eq("id", profileId);
}

export async function transferTeam(teamId: string, profileId: string) {
  const user = await requireUser();
  if (user.role !== "owner") return { ok: false };
  const admin = createSupabaseAdmin();
  await admin.from("teams").update({ owner: profileId }).eq("id", teamId);
  return { ok: true };
}
