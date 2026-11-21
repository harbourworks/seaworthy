import OpenAI from "openai";
import { unlimitedPlan, wordBudget } from "@/lib/plans";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(request: Request) {
  const { text, plan } = await request.json();
  const budget = wordBudget(plan ?? unlimitedPlan);
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: `Summarise in under ${budget} words:\n\n${text}` }],
  });
  return Response.json({ summary: completion.choices[0]?.message.content });
}
