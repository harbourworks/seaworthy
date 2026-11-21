import OpenAI from "openai";
import { checkRateLimit } from "../../../lib/limits";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(request: Request) {
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  if (!(await checkRateLimit(`summarise:${ip}`, 20, 60))) {
    return new Response("Too Many Requests", { status: 429, headers: { "Retry-After": "60" } });
  }
  const { text } = await request.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: `Summarise:\n\n${text}` }],
  });
  return Response.json({ summary: completion.choices[0]?.message.content });
}
