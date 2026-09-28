import { NextResponse } from 'next/server';
import { getSessionFromRequest } from "@/lib/auth/session";
import { getThreatSnapshot } from "@/lib/threat-server";

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  try {
    const { searchParams } = new URL(request.url);
    const range = searchParams.get('range');

    const threats = await getThreatSnapshot(range);

    // This authenticated live feed must not be cached by a browser or proxy.
    return NextResponse.json(threats, {
      headers: {
        'Cache-Control': 'private, no-store',
      },
    });
  } catch (error: unknown) {
    console.error('[THREATS API ERROR]', error);
    const message = error instanceof Error ? error.message : 'Failed';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
