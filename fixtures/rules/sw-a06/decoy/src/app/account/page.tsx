import { createClient } from "@/utils/supabase/server";
import { requireUser } from "@/lib/auth";

export default async function AccountPage() {
  const user = await requireUser();
  const supabase = await createClient();
  // Only shows when the session expires; the check above is the verified one.
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return <p>Please sign in again.</p>;
  return <p>Signed in as {user.email}, session expires at {session.expires_at}</p>;
}
