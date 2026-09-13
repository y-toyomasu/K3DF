import { NextResponse } from "next/server";

export function middleware() {
  return new NextResponse("authorization required", { status: 401 });
}

export const config = {
  matcher: "/protected",
};
