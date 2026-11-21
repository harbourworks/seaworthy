import { requireUser } from "@/lib/auth";
import { createSupabaseAdmin } from "@/lib/admin";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await requireUser();
  const admin = createSupabaseAdmin();
  const { data } = await admin.from("notes").select("*").eq("id", params.id).eq("user_id", user.id).single();
  if (!data) return new Response(null, { status: 404 });
  return Response.json(data);
}
