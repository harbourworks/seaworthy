import { createClient } from "@/utils/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { data } = await supabase.from("invoices").select("*").eq("user_id", session.user.id);
  return Response.json(data);
}
