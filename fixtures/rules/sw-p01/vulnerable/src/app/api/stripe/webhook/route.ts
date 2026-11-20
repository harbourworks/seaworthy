import type Stripe from "stripe";
import { handleStripeEvent } from "@/services/billing/webhookHandler";

export async function POST(req: Request) {
  const event = (await req.json()) as Stripe.Event;
  await handleStripeEvent(event);
  return new Response("ok");
}
