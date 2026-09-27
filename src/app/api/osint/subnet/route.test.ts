import { describe, it, expect } from 'vitest';
import { NextRequest } from 'next/server';
import { GET, POST } from './route';

describe('OSINT Subnet API Route', () => {
  it('returns 400 when cidr parameter is missing', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/subnet');
    const res = await GET(req);
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.status).toBe('error');
  });

  it('returns 400 when cidr parameter is invalid', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/subnet?cidr=invalid');
    const res = await GET(req);
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.status).toBe('error');
  });

  it('parses valid CIDR 192.168.1.0/24 correctly', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/subnet?cidr=192.168.1.0/24');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('success');
    expect(data.cidr).toBe('192.168.1.0/24');
    expect(data.total_hosts).toBe(256);
    expect(data.usable_hosts).toBe(254);
    expect(data.is_private).toBe(true);
    expect(data.sample_hosts.length).toBeGreaterThan(0);
  });

  it('handles POST requests with CIDR payload', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/subnet', {
      method: 'POST',
      body: JSON.stringify({ cidr: '10.0.0.0/16' }),
    });
    const res = await POST(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('success');
    expect(data.prefixlen).toBe(16);
    expect(data.is_private).toBe(true);
  });
});
