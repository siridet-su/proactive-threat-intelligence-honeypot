import { NextResponse } from 'next/server';
import clientPromise from '@/lib/mongodb';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  try {
    const client = await clientPromise;
    const db = client.db('honeypot_db');
    const collection = db.collection('hardware_metrics');

    const stream = new ReadableStream({
      async start(controller) {
        // 1. Send the initial payload (latest 30 items) so the chart isn't empty
        const initialData = await collection
          .find({})
          .sort({ timestamp: -1 })
          .limit(30)
          .toArray();
        
        // Reverse so the oldest of the 30 is first
        const reversed = initialData.reverse();
        controller.enqueue(`data: ${JSON.stringify({ type: 'initial', data: reversed })}\n\n`);

        // 2. Open a Change Stream to listen for new inserts in real-time
        const changeStream = collection.watch([{ $match: { operationType: 'insert' } }]);

        changeStream.on('change', (change: any) => {
          if (change.operationType === 'insert') {
            controller.enqueue(`data: ${JSON.stringify({ type: 'update', data: change.fullDocument })}\n\n`);
          }
        });

        changeStream.on('error', (err) => {
          console.error("Change stream error:", err);
          controller.close();
        });

        // 3. Clean up when the client disconnects (e.g., user closes browser tab)
        req.signal.addEventListener('abort', () => {
          changeStream.close();
          controller.close();
        });
      }
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
      },
    });
  } catch (e: any) {
    console.error('Failed to initialize SSE stream:', e);
    return NextResponse.json({ error: e.message || 'Failed to start stream' }, { status: 500 });
  }
}
