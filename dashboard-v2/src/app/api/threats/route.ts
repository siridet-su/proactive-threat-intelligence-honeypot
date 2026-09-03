import { NextResponse } from 'next/server';
import clientPromise from '@/lib/mongodb';
import geoip from 'geoip-lite';
import type { Filter, Document } from "mongodb";

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const range = searchParams.get('range');

    const client = await clientPromise;
    const db = client.db('honeypot_canonical_v1'); 

    let query: Filter<Document> = {};
    if (range === '7days') {
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      query = { start_time: { $gte: sevenDaysAgo.toISOString() } };
    }

    const limitCount = range === 'all' ? 2000 : 100;

    const sessionDocs = await db.collection('sessions')
      .find(query)
      .sort({ start_time: -1 })
      .limit(limitCount)
      .toArray();

    // ระบบจดจำพิกัด IP (Cache) เพื่อไม่ต้องประมวลผล IP เดิมซ้ำ
    const ipCache = new Map();

    const threats = sessionDocs.map(session => {
      let lat = 0, lon = 0, country = 'Unknown', city = 'Unknown';
      const ip = session.src_ip || 'Unknown';
      
      if (ip !== 'Unknown') {
        if (ipCache.has(ip)) {
          const cached = ipCache.get(ip);
          lat = cached.lat; lon = cached.lon;
          country = cached.country; city = cached.city;
        } else {
          const geo = geoip.lookup(ip);
          if (geo) {
            lat = geo.ll[0]; lon = geo.ll[1];
            country = geo.country; city = geo.city;
            ipCache.set(ip, { lat, lon, country, city });
          } else {
            ipCache.set(ip, { lat: 0, lon: 0, country: 'Unknown', city: 'Unknown' });
          }
        }
      }

      let dateObj = new Date();
      if (session.start_time) {
        const parsed = new Date(session.start_time);
        if (!isNaN(parsed.getTime())) dateObj = parsed;
      }

      const severity = session.max_confirmed_severity || 'Medium';
      let classification = 'SCRIPT KIDDIE';
      let typeColor = 'bg-amber-950/40 text-amber-400 border-amber-900/50';
      
      if (severity === 'Critical') {
        classification = 'APT';
        typeColor = 'bg-red-950/40 text-red-400 border-red-900/50';
      } else if (severity === 'High') {
        classification = 'BOT';
        typeColor = 'bg-slate-800 text-slate-300 border-slate-700';
      }

      return {
        id: session.session_id || session._id?.toString() || Math.random().toString(),
        timestamp: dateObj.toISOString(),
        date: dateObj.toLocaleDateString('en-GB'),
        time: dateObj.toLocaleTimeString('en-US', { hour12: false }) + " UTC",
        sensor: session.session_source || 'Unknown',
        src_ip: ip,
        sourceIp: ip,
        severity: severity,
        classification: classification,
        typeColor: typeColor,
        duration: 'Active',
        geo: { lat, lon, country, city }
      };
    });

    // ตั้งค่า Cache 5 วินาที ลดการดึงข้อมูลซ้ำซ้อนจากหลายคอมโพเนนต์
    return NextResponse.json(threats, {
      headers: {
        'Cache-Control': 'public, s-maxage=5, stale-while-revalidate=10',
      },
    });
  } catch (error: unknown) {
    console.error('[THREATS API ERROR]', error);
    const message = error instanceof Error ? error.message : 'Failed';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}