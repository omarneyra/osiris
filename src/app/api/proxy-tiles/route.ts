import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url');

  if (!url) {
    return NextResponse.json({ error: 'Missing url parameter' }, { status: 400 });
  }

  try {
    // Only allow cartocdn.com domains to prevent open proxy abuse
    const targetUrl = new URL(url);
    const host = targetUrl.hostname.toLowerCase();
    if (host !== 'cartocdn.com' && !host.endsWith('.cartocdn.com')) {
      return NextResponse.json({ error: 'Forbidden domain' }, { status: 403 });
    }

    const response = await fetch(targetUrl.toString(), {
      signal: AbortSignal.timeout(10000),
      headers: {
        'Accept': '*/*',
        'User-Agent': 'Osiris-Tile-Proxy/1.0',
      },
      next: {
        revalidate: 31536000, // Cache for 1 year
      },
    });

    if (!response.ok) {
      return NextResponse.json({ error: 'Tile not available' }, { status: 404 });
    }

    const data = await response.arrayBuffer();
    const contentType = response.headers.get('content-type') || 'application/octet-stream';

    return new NextResponse(data, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=31536000, immutable',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (error: any) {
    // Graceful fallback for tile fetching timeouts / network drops to prevent 500 overlays
    return NextResponse.json({ error: 'Tile unavailable', details: error?.message }, { status: 404 });
  }
}
