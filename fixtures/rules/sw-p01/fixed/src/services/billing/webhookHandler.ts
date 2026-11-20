import type Stripe from "stripe";

export async function handleStripeEvent(event: Stripe.Event) {
  switch (event.type) {
    case "checkout.session.completed":
      await markPaid(event.data.object as Stripe.Checkout.Session);
      break;
    case "customer.subscription.deleted":
      break;
  }
}

async function markPaid(session: Stripe.Checkout.Session) {
  console.log("paid", session.id);
}
