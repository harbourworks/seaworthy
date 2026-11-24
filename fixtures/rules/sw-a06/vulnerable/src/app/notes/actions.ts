"use server";
import { createClient } from "@/utils/supabase/server";

export async function addNote(body: string) {
  const supabase = await createClient();
  const session = (await supabase.auth.getSession()).data.session;
  const userId = session?.user.id;
  await supabase.from("notes").insert({ body, user_id: userId });
}
