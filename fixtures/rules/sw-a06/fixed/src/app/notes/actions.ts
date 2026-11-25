"use server";
import { createClient } from "@/utils/supabase/server";

export async function addNote(body: string) {
  const supabase = await createClient();
  const { data } = await supabase.auth.getClaims();
  if (!data?.claims) throw new Error("Not signed in");
  await supabase.from("notes").insert({ body, user_id: data.claims.sub });
}
