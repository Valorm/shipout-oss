import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  const redirectUrl = new URL('/api-edge/scan', req.url);
  return NextResponse.redirect(redirectUrl, 308);
}
