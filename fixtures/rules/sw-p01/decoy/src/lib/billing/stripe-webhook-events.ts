import type Stripe from "stripe";

/** Called only with events the route has already verified. */
export async function onStripeEvent(event: Stripe.Event): Promise<void> {
  if (event.type === "invoice.paid") {
    console.log("invoice paid", event.data.object.id);
  } else if (event.type === "customer.subscription.updated") {
    console.log("subscription updated", event.data.object.id);
  }
}
