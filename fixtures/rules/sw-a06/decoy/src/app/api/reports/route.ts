import { createClient } from "@/utils/supabase/server";

export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });

  // The access token, for the reporting service, after the user is verified.
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return new Response("Session expired", { status: 401 });
  const res = await fetch(process.env.REPORTS_URL!, {
    method: "POST",
    headers: { Authorization: `Bearer ${session.access_token}` },
    body: JSON.stringify({ owner: user.id, ...(await req.json()) }),
  });
  return new Response(res.body, { status: res.status });
}
