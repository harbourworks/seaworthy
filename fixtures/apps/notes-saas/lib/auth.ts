import { supabaseAdmin } from "./supabase-server";

export async function getUser(req: Request) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) return null;
  const { data } = await supabaseAdmin.auth.getUser(token);
  return data.user ?? null;
}
