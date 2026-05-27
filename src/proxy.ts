import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

export default auth((req) => {
  const { pathname } = req.nextUrl;
  const isAuthenticated = !!req.auth;

  // Protect dashboard routes and API mutation routes
  const isProtectedPath =
    pathname.startsWith("/dashboard") ||
    pathname.startsWith("/rules") ||
    pathname.startsWith("/logs") ||
    pathname.startsWith("/api/rules") ||
    pathname.startsWith("/api/logs");

  if (isProtectedPath && !isAuthenticated) {
    const loginUrl = new URL("/login", req.url);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Allow proxy route without auth — it uses its own API key header
  return NextResponse.next();
});

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|wasm|api/auth|login).*)",
  ],
};
