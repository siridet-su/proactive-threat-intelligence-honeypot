import { NextResponse } from 'next/server';
import clientPromise from '@/lib/mongodb';
import geoip from 'geoip-lite';

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
        geo: {
          lat,
          lon,
          country,
          city
        }
      };
    });

    return NextResponse.json(threats);
  } catch (e: any) {
    console.error('Failed to fetch threats:', e);
    return NextResponse.json({ error: e.message || 'Failed to fetch threats' }, { status: 500 });
  }
}
