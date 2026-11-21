import { NextResponse, type NextRequest } from "next/server";
import { isRateLimited } from "@/lib/rate-limit";

export function middleware(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  if (request.nextUrl.pathname.startsWith("/api/") && isRateLimited(ip, 100, 60_000)) {
    return new NextResponse("Too Many Requests", { status: 429 });
  }
  return NextResponse.next();
}
