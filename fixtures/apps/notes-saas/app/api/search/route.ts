import { NextResponse } from "next/server";
import { pool } from "@/lib/db";
import { getUser } from "@/lib/auth";

export async function GET(req: Request) {
  const user = await getUser(req);
  if (!user) {
    return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  }

  const q = new URL(req.url).searchParams.get("q") ?? "";
  const result = await pool.query(
    "SELECT id, title FROM notes WHERE user_id = '" + user.id + "' AND title ILIKE '%" + q + "%'"
  );
  return NextResponse.json(result.rows);
}
