import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

interface EnrichmentResponse {
  status: 'success' | 'error';
  type: string;
  target: string;
  risk_score: number;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  indicators: string[];
  details: Record<string, any>;
  timestamp: string;
}

function detectType(target: string): 'ip' | 'vessel' | 'aircraft' {
  const clean = target.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean)) return 'ip';
  if (/^\d{9}$/.test(clean)) return 'vessel';
  return 'aircraft';
}

function calculateRisk(indicators: string[]): { score: number; level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' } {
  const weights: Record<string, number> = {
    TOR_EXIT_NODE: 35,
    KNOWN_MALWARE_C2: 50,
    SANCTIONED_ENTITY: 60,
    MILITARY_TRANSPONDER: 25,
    HIGH_RISK_FLAG_STATE: 30,
    INTERNAL_NETWORK: 10,
  };

  const score = Math.min(100, indicators.reduce((acc, ind) => acc + (weights[ind] || 10), 0));
  let level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (score >= 75) level = 'CRITICAL';
  else if (score >= 50) level = 'HIGH';
  else if (score >= 25) level = 'MEDIUM';

  return { score, level };
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const target = searchParams.get('target');
  let type = searchParams.get('type') as 'ip' | 'vessel' | 'aircraft' | null;

  if (!target) {
    return NextResponse.json({ status: 'error', message: 'Target query parameter is required' }, { status: 400 });
  }

  const cleanTarget = target.trim();
  if (!type || type === 'auto' as any) {
    type = detectType(cleanTarget);
  }

  const indicators: string[] = [];
  const details: Record<string, any> = {};

  if (type === 'ip') {
    const parts = cleanTarget.split('.').map(Number);
    const isPrivate =
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127;

    if (isPrivate) indicators.push('INTERNAL_NETWORK');
    details.is_private = isPrivate;
    details.query_ip = cleanTarget;
  } else if (type === 'vessel') {
    const midCode = cleanTarget.slice(0, 3);
    if (['677', '668', '620'].includes(midCode)) {
      indicators.push('HIGH_RISK_FLAG_STATE');
    }
    details.mmsi = cleanTarget;
    details.mid_code = midCode;
  } else if (type === 'aircraft') {
    const upperCallsign = cleanTarget.toUpperCase();
    const milPrefixes = ['RCH', 'CNV', 'CGR', 'FORTE', 'LAGR', 'HOMER', 'DUKE', 'NACHO', 'JAKE'];
    if (milPrefixes.some(p => upperCallsign.startsWith(p))) {
      indicators.push('MILITARY_TRANSPONDER');
    }
    details.icao24_or_callsign = cleanTarget;
  }

  const { score, level } = calculateRisk(indicators);

  const response: EnrichmentResponse = {
    status: 'success',
    type,
    target: cleanTarget,
    risk_score: score,
    threat_level: level,
    indicators,
    details,
    timestamp: new Date().toISOString(),
  };

  return NextResponse.json(response);
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { target, type } = body;

    if (!target) {
      return NextResponse.json({ status: 'error', message: 'Target field is required' }, { status: 400 });
    }

    const url = new URL(req.url);
    url.searchParams.set('target', target);
    if (type) url.searchParams.set('type', type);

    const syntheticReq = new NextRequest(url.toString(), { method: 'GET' });
    return GET(syntheticReq);
  } catch {
    return NextResponse.json({ status: 'error', message: 'Invalid JSON body' }, { status: 400 });
  }
}
