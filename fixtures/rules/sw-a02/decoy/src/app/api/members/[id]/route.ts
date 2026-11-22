import { requireUser } from "@/lib/auth";
import { createSupabaseAdmin } from "@/lib/admin";

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const user = await requireUser();
  if (!user || (user.role !== "owner" && user.role !== "admin")) {
    return new Response(null, { status: 403 });
  }
  const admin = createSupabaseAdmin();
  await admin.from("profiles").delete().eq("id", params.id);
  return new Response(null, { status: 204 });
}
