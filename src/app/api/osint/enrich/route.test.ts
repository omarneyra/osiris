import { describe, it, expect } from 'vitest';
import { NextRequest } from 'next/server';
import { GET, POST } from './route';

describe('OSINT Enrich API Route', () => {
  it('returns 400 when target parameter is missing', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/enrich');
    const res = await GET(req);
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.status).toBe('error');
  });

  it('enriches IP address targets automatically', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/enrich?target=192.168.1.100');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('success');
    expect(data.type).toBe('ip');
    expect(data.indicators).toContain('INTERNAL_NETWORK');
    expect(data.details.is_private).toBe(true);
  });

  it('enriches vessel MMSI targets automatically', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/enrich?target=677123456');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('success');
    expect(data.type).toBe('vessel');
    expect(data.indicators).toContain('HIGH_RISK_FLAG_STATE');
  });

  it('enriches military aircraft callsigns', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/enrich?target=FORTE11');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('success');
    expect(data.type).toBe('aircraft');
    expect(data.indicators).toContain('MILITARY_TRANSPONDER');
  });

  it('handles POST requests with JSON payload', async () => {
    const req = new NextRequest('http://localhost:3000/api/osint/enrich', {
      method: 'POST',
      body: JSON.stringify({ target: '10.0.0.1', type: 'ip' }),
    });
    const res = await POST(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('success');
    expect(data.target).toBe('10.0.0.1');
  });
});
