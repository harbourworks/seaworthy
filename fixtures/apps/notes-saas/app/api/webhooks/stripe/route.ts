import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase-server";

export async function POST(req: Request) {
  const event = JSON.parse(await req.text());

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    await supabaseAdmin
      .from("payments")
      .insert({ user_id: session.client_reference_id, amount: session.amount_total });
    await supabaseAdmin
      .from("profiles")
      .update({ plan: "pro" })
      .eq("id", session.client_reference_id);
  }

  return NextResponse.json({ received: true });
}
