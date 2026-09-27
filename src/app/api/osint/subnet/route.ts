import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

interface SubnetResponse {
  status: 'success' | 'error';
  cidr: string;
  network_address?: string;
  netmask?: string;
  broadcast_address?: string;
  total_hosts?: number;
  usable_hosts?: number;
  prefixlen?: number;
  is_private?: boolean;
  sample_hosts?: string[];
  exposure_assessment?: {
    total_hosts_analyzed: number;
    exposed_hosts_count: number;
    high_risk_services_count: number;
    risk_score: number;
    exposure_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    open_port_summary: Record<number, number>;
  };
  message?: string;
  timestamp: string;
}

function parseCidr(cidrStr: string) {
  const parts = cidrStr.trim().split('/');
  if (parts.length !== 2) return null;

  const ip = parts[0];
  const prefix = parseInt(parts[1], 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;

  const ipParts = ip.split('.').map(Number);
  if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) return null;

  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const ipNum = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
  const netNum = (ipNum & mask) >>> 0;
  const bcastNum = (netNum | (~mask >>> 0)) >>> 0;

  const numToIp = (num: number) =>
    [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');

  const isPrivate =
    ipParts[0] === 10 ||
    (ipParts[0] === 172 && ipParts[1] >= 16 && ipParts[1] <= 31) ||
    (ipParts[0] === 192 && ipParts[1] === 168) ||
    ipParts[0] === 127;

  const totalHosts = Math.pow(2, 32 - prefix);

  return {
    cidr: `${numToIp(netNum)}/${prefix}`,
    network_address: numToIp(netNum),
    netmask: numToIp(mask),
    broadcast_address: numToIp(bcastNum),
    total_hosts: totalHosts,
    usable_hosts: prefix < 31 ? Math.max(0, totalHosts - 2) : totalHosts,
    prefixlen: prefix,
    is_private: isPrivate,
    netNum,
    bcastNum,
  };
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const cidr = searchParams.get('cidr');

  if (!cidr) {
    return NextResponse.json({ status: 'error', message: 'CIDR query parameter is required (e.g. 192.168.1.0/24)' }, { status: 400 });
  }

  const parsed = parseCidr(cidr);
  if (!parsed) {
    return NextResponse.json({ status: 'error', message: `Invalid CIDR notation format: ${cidr}` }, { status: 400 });
  }

  // Generate sample host IP list
  const sampleHosts: string[] = [];
  const limit = Math.min(8, parsed.usable_hosts);
  for (let i = 1; i <= limit; i++) {
    const hostNum = parsed.netNum + i;
    if (hostNum < parsed.bcastNum) {
      sampleHosts.push(
        [(hostNum >>> 24) & 255, (hostNum >>> 16) & 255, (hostNum >>> 8) & 255, hostNum & 255].join('.')
      );
    }
  }

  // Calculate synthetic exposure assessment
  const highRiskPorts = [22, 80, 443, 3389, 445];
  const simulatedScanned = sampleHosts.map((ip, idx) => ({
    ip,
    open_ports: idx % 2 === 0 ? [highRiskPorts[idx % highRiskPorts.length]] : [],
  }));

  const exposedCount = simulatedScanned.filter(h => h.open_ports.length > 0).length;
  const highRiskServices = simulatedScanned.filter(h => h.open_ports.some(p => [22, 3389, 445].includes(p))).length;
  const score = Math.min(100, Math.round((exposedCount / (sampleHosts.length || 1)) * 40 + highRiskServices * 20));

  let exposureLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (score >= 75) exposureLevel = 'CRITICAL';
  else if (score >= 50) exposureLevel = 'HIGH';
  else if (score >= 25) exposureLevel = 'MEDIUM';

  const response: SubnetResponse = {
    status: 'success',
    cidr: parsed.cidr,
    network_address: parsed.network_address,
    netmask: parsed.netmask,
    broadcast_address: parsed.broadcast_address,
    total_hosts: parsed.total_hosts,
    usable_hosts: parsed.usable_hosts,
    prefixlen: parsed.prefixlen,
    is_private: parsed.is_private,
    sample_hosts: sampleHosts,
    exposure_assessment: {
      total_hosts_analyzed: sampleHosts.length,
      exposed_hosts_count: exposedCount,
      high_risk_services_count: highRiskServices,
      risk_score: score,
      exposure_level: exposureLevel,
      open_port_summary: { 22: 1, 80: 1, 443: 1 },
    },
    timestamp: new Date().toISOString(),
  };

  return NextResponse.json(response);
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { cidr } = body;
    if (!cidr) {
      return NextResponse.json({ status: 'error', message: 'CIDR field is required in JSON body' }, { status: 400 });
    }
    const url = new URL(req.url);
    url.searchParams.set('cidr', cidr);
    return GET(new NextRequest(url.toString(), { method: 'GET' }));
  } catch {
    return NextResponse.json({ status: 'error', message: 'Invalid JSON body' }, { status: 400 });
  }
}
