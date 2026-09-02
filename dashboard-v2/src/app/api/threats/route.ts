import { NextResponse } from 'next/server';
import clientPromise from '@/lib/mongodb';
import geoip from 'geoip-lite';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const client = await clientPromise;
    const db = client.db('honeypot_db');
    
    const events = await db
      .collection('events')
      .find({})
      .sort({ timestamp: -1 })
      .limit(100)
      .toArray();

    const threats = events.map(event => {
      let lat = 0;
      let lon = 0;
      let country = 'Unknown';
      let city = 'Unknown';
      
      const ip = event.src_ip || event.source_ip || event.ip || 'Unknown';
      
      if (ip !== 'Unknown') {
        const geo = geoip.lookup(ip);
        if (geo) {
          lat = geo.ll[0];
          lon = geo.ll[1];
          country = geo.country;
          city = geo.city;
        }
      }

      const sensorName = typeof event.sensor === 'object' && event.sensor !== null
        ? (event.sensor.name || 'Unknown') 
        : (event.sensor || 'Unknown');

      const payloadStr = typeof event.payload === 'object' && event.payload !== null
        ? JSON.stringify(event.payload) 
        : (event.payload || '');

      return {
        id: event._id.toString(),
        timestamp: event.timestamp || new Date().toISOString(),
        sensor: sensorName,
        event_type: event.event_type || event.event || 'Unknown',
        src_ip: ip,
        sourceIp: ip,
        protocol: event.protocol || 'TCP',
        payloadPreview: payloadStr.substring(0, 80) || 'No payload data',
        severity: event.severity || (sensorName.toLowerCase().includes('cowrie') ? 'High' : 'Medium'),
        geo: { lat, lon, country, city }
      };
    });

    return NextResponse.json(threats);
  } catch (error: any) {
    console.error('Failed to fetch threats:', error);
    return NextResponse.json(
      { error: error?.message || 'Failed to fetch threats' }, 
      { status: 500 }
    );
  }
}