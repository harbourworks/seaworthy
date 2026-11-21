import { sendMail } from "@/lib/mail";
import { guard } from "@/lib/guard";

export async function POST(request: Request) {
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  if (!(await guard(ip))) return new Response("Too Many Requests", { status: 429 });
  const { email } = await request.json();
  await sendMail(email, "You are invited", "Join us at https://app.example.com");
  return Response.json({ ok: true });
}
