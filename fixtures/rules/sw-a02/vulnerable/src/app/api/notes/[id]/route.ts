import { requireUser } from "@/lib/auth";
import { createSupabaseAdmin } from "@/lib/admin";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  await requireUser();
  const admin = createSupabaseAdmin();
  const { data } = await admin.from("notes").select("*").eq("id", params.id).single();
  return Response.json(data);
}
