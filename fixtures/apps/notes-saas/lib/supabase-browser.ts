import { createClient } from "@supabase/supabase-js";

// Uses the service role so the notes page can read everything without fighting RLS.
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);
