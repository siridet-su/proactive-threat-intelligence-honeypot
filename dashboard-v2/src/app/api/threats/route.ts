import { NextResponse } from 'next/server';
import clientPromise from '@/lib/mongodb';
import geoip from 'geoip-lite';

type ThreatIntelResult<T> = {
  status?: string;
  summary?: T;
};

type AbuseIPDBSummary = {
  abuse_confidence_score?: number;
  total_reports?: number;
  country_code?: string;
  domain?: string;
  isp?: string;
  is_tor?: boolean;
  usage_type?: string;
};

type VirusTotalSummary = {
  meaningful_name?: string;
  reputation?: number;
  analysis_stats?: {
    malicious?: number;
    undetected?: number;
  };
};

type DashboardThreatEvent = {
  [key: string]: unknown;
  abuseipdb?: unknown;
  virustotal?: unknown;
  threat_intel?: {
    abuseipdb?: ThreatIntelResult<AbuseIPDBSummary>;
    virustotal?: ThreatIntelResult<VirusTotalSummary>;
  };
};

// The worker stores provider-neutral records under threat_intel. Keep this
// adapter while existing dashboard components consume the earlier provider
// shapes, so old historical events and new asynchronous results coexist.
function abuseIPDBForDashboard(event: DashboardThreatEvent) {
  if (event.abuseipdb) return event.abuseipdb;

  const result = event.threat_intel?.abuseipdb;
  if (result?.status !== 'complete' || !result.summary) return null;

  return {
    abuseConfidenceScore: result.summary.abuse_confidence_score ?? 0,
    totalReports: result.summary.total_reports ?? 0,
    countryCode: result.summary.country_code ?? null,
    domain: result.summary.domain ?? null,
    isp: result.summary.isp ?? null,
    isTor: result.summary.is_tor ?? false,
    usageType: result.summary.usage_type ?? null,
  };
}

function virusTotalForDashboard(event: DashboardThreatEvent) {
  if (event.virustotal) return event.virustotal;

  const result = event.threat_intel?.virustotal;
  if (result?.status !== 'complete' || !result.summary) return null;

  const stats = result.summary.analysis_stats || {};
  return {
    attributes: {
      meaningful_name: result.summary.meaningful_name ?? null,
      reputation: result.summary.reputation ?? 0,
      stats: {
        malicious: stats.malicious ?? 0,
        undetected: stats.undetected ?? 0,
      },
    },
  };
}

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const client = await clientPromise;
    const db = client.db('honeypot_db');
    
    // Fetch latest 100 events
    const events = await db
      .collection('events')
      .find({})
      .sort({ timestamp: -1 })
      .limit(100)
      .toArray();

    // Map events and resolve Geo-IP
    const threats = events.map(event => {
      let lat = 0;
      let lon = 0;
      let country = 'Unknown';
      let city = 'Unknown';
      
      const ip = event.network?.src_ip || event.src_ip || event.raw?.payload?.src_ip || 'Unknown IP';
      
      if (ip && ip !== 'Unknown IP') {
        const geo = geoip.lookup(ip);
        if (geo) {
          lat = geo.ll[0];
          lon = geo.ll[1];
          country = geo.country;
          city = geo.city;
        }
      }

      return {
        id: event._id.toString(),
        timestamp: event.timestamp || new Date().toISOString(),
        sensor: event.source || (typeof event.sensor === 'object' ? event.sensor.name : event.sensor) || 'Unknown',
        event_type: event.event_type || event.event || 'Unknown',
        src_ip: ip,
        sourceIp: ip,
        src_port: event.network?.src_port || event.src_port || null,
        dest_port: event.network?.dst_port || event.dest_port || null,
        protocol: event.network?.protocol || event.protocol || 'TCP',
        payload: event.payload || '',
        payloadPreview: event.payload || event.event_type || 'Unknown Event',
        severity: event.severity || (event.sensor === 'cowrie' ? 'High' : 'Medium'),
        abuseipdb: abuseIPDBForDashboard(event),
        virustotal: virusTotalForDashboard(event),
        geo: {
          lat,
          lon,
          country,
          city
        }
      };
    });

    return NextResponse.json(threats);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Failed to fetch threats';
    console.error('Failed to fetch threats:', error);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
