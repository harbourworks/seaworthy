import { createClient } from "@/utils/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data } = await supabase.from("invoices").select("*").eq("user_id", user.id);
  return Response.json(data);
}
