import { createClient } from "@supabase/supabase-js";

/** Skips row-level security: every query through it needs its own access check. */
export function createSupabaseAdmin() {
  return createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
}
