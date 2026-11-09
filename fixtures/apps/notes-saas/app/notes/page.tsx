"use client";

import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabase-browser";

type Note = { id: string; title: string; body: string };

export default function NotesPage() {
  const [notes, setNotes] = useState<Note[]>([]);

  useEffect(() => {
    supabase
      .from("notes")
      .select("*")
      .then(({ data }) => setNotes(data ?? []));
  }, []);

  return (
    <main>
      <h1>Your notes</h1>
      <ul>
        {notes.map((n) => (
          <li key={n.id}>{n.title}</li>
        ))}
      </ul>
    </main>
  );
}
