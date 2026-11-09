import { NextResponse } from "next/server";
import { stripe } from "@/lib/stripe";
import { getUser } from "@/lib/auth";

export async function POST(req: Request) {
  const user = await getUser(req);
  if (!user) {
    return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  }

  const { plan, amount } = await req.json();

  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [
      {
        price_data: {
          currency: "gbp",
          product_data: { name: `Notes ${plan}` },
          unit_amount: amount,
        },
        quantity: 1,
      },
    ],
    success_url: "https://notes.example.com/thanks",
    cancel_url: "https://notes.example.com/pricing",
    client_reference_id: user.id,
  });

  return NextResponse.json({ url: session.url });
}
