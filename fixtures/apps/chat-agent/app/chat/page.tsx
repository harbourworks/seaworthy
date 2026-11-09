"use client";

import { useState } from "react";
import { openai } from "@/lib/openai-browser";

export default function ChatPage() {
  const [input, setInput] = useState("");
  const [reply, setReply] = useState("");

  async function send() {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a helpful assistant. Reply in HTML." },
        { role: "user", content: input },
      ],
    });
    setReply(completion.choices[0].message.content ?? "");
  }

  return (
    <main>
      <textarea value={input} onChange={(e) => setInput(e.target.value)} />
      <button onClick={send}>Send</button>
      <div dangerouslySetInnerHTML={{ __html: reply }} />
    </main>
  );
}
