import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase-server";
import { getUser } from "@/lib/auth";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await getUser(req);
  if (!user) {
    return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  }

  const { data, error } = await supabaseAdmin
    .from("notes")
    .select("*")
    .eq("id", params.id)
    .single();

  if (error) return NextResponse.json({ error: error.message }, { status: 404 });
  return NextResponse.json(data);
}

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await supabaseAdmin.from("notes").delete().eq("id", params.id);
  return NextResponse.json({ ok: true });
}
