import { NextResponse } from "next/server";

export async function GET(req: Request) {
  const incomingUrl = new URL(req.url);
  const redirectPath = incomingUrl.pathname.replace('/api/scan/', '/api-edge/scan/');
  const redirectUrl = new URL(redirectPath, req.url);

  return NextResponse.redirect(redirectUrl, 308);
}
