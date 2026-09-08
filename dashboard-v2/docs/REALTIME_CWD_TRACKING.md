# Real-time Attacker Directory Tracking (CWD)

## ภาพรวม

เป้าหมายคือแสดง **current working directory (CWD)** ที่ผู้โจมตีแต่ละ session อยู่ใน Cowrie แบบ real-time บน dashboard

---

## โครงสร้างข้อมูลที่มีอยู่ใน MongoDB

Cowrie เก็บทุก command ที่ attacker พิมพ์ใน collection `honeypot_db.events` โดย event ที่เกี่ยวข้องมี 2 รูปแบบ:

### `event_type: "ssh_command"` (จาก processor pipeline)
```json
{
  "event_type": "ssh_command",
  "session": { "id": "821841d4faeb" },
  "timestamp": "2026-08-04T21:21:04.129364Z",
  "network": { "src_ip": "202.28.41.152" },
  "raw": {
    "payload": {
      "eventid": "cowrie.command.input",
      "input": "cd opt",
      "message": "CMD: cd opt",
      "session": "821841d4faeb"
    }
  }
}
```

### `event_type: "cowrie.command.input"` (raw cowrie log)
```json
{
  "event_type": "cowrie.command.input",
  "raw": {
    "payload": {
      "input": "cd odoo",
      "session": "821841d4faeb"
    }
  }
}
```

> **หมายเหตุ**: Cowrie ไม่ได้เก็บ CWD โดยตรง — มีแค่ `input` (command ที่พิมพ์) ต้อง compute จาก cd history เอง

---

## แนวทางที่ 1: Command History Simulation (แนะนำ)

### หลักการ

ดึง `ssh_command` events ทั้งหมดของ session → เรียงตาม timestamp → simulate filesystem navigation

```
session 821841d4faeb (src: 202.28.41.152):
  [login]         → cwd = /root
  CMD: cd opt     → cwd = /opt
  CMD: cd odoo    → cwd = /opt/odoo
  CMD: ls         → cwd = /opt/odoo  (unchanged)
  CMD: cd ..      → cwd = /opt
  CMD: cd /tmp    → cwd = /tmp
  CMD: cd ~       → cwd = /root
```

### CWD Simulation Logic

```typescript
// src/lib/cwdTracker.ts

export function computeCwd(commands: string[], startDir = '/root'): string {
  let cwd = startDir;

  for (const raw of commands) {
    const cmd = raw.trim();
    if (!cmd.startsWith('cd')) continue;

    const arg = cmd.slice(2).trim();

    if (!arg || arg === '~') {
      cwd = '/root';
    } else if (arg === '-') {
      // cd - ไม่ track OLDPWD ใน scope นี้ ข้ามไป
      continue;
    } else if (arg.startsWith('/')) {
      // absolute path
      cwd = arg.replace(/\/+$/, '') || '/';
    } else if (arg === '..') {
      const parts = cwd.split('/').filter(Boolean);
      parts.pop();
      cwd = '/' + parts.join('/');
    } else {
      // relative path
      cwd = (cwd === '/' ? '' : cwd) + '/' + arg;
    }

    // normalize double slashes
    cwd = cwd.replace(/\/+/g, '/') || '/';
  }

  return cwd;
}
```

### API Endpoint

```typescript
// src/app/api/sessions/[sessionId]/cwd/route.ts
import { NextResponse } from 'next/server';
import clientPromise from '@/lib/mongodb';
import { computeCwd } from '@/lib/cwdTracker';

export const dynamic = 'force-dynamic';

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  const { sessionId } = await params;
  const client = await clientPromise;
  const db = client.db('honeypot_db');

  const events = await db.collection('events')
    .find({
      'session.id': sessionId,
      event_type: { $in: ['ssh_command', 'cowrie.command.input'] }
    })
    .sort({ timestamp: 1 })
    .toArray();

  const commands = events.map(e =>
    e.raw?.payload?.input ?? e.activity?.command ?? ''
  ).filter(Boolean);

  const cwd = computeCwd(commands);
  const lastCmd = commands[commands.length - 1] ?? null;

  return NextResponse.json({ sessionId, cwd, commandCount: commands.length, lastCmd });
}
```

### Real-time SSE Endpoint

```typescript
// src/app/api/sessions/[sessionId]/cwd/stream/route.ts
import clientPromise from '@/lib/mongodb';
import { computeCwd } from '@/lib/cwdTracker';

export const dynamic = 'force-dynamic';

export async function GET(
  req: Request,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  const { sessionId } = await params;
  const client = await clientPromise;
  const db = client.db('honeypot_db');

  // โหลด command history เดิมทั้งหมดก่อน
  const existing = await db.collection('events')
    .find({
      'session.id': sessionId,
      event_type: { $in: ['ssh_command', 'cowrie.command.input'] }
    })
    .sort({ timestamp: 1 })
    .toArray();

  const commands: string[] = existing.map(e =>
    e.raw?.payload?.input ?? e.activity?.command ?? ''
  ).filter(Boolean);

  const stream = new ReadableStream({
    async start(controller) {
      // ส่ง initial CWD
      const initialCwd = computeCwd(commands);
      controller.enqueue(
        `data: ${JSON.stringify({ type: 'initial', cwd: initialCwd, commands })}\n\n`
      );

      // Watch เฉพาะ ssh_command ของ session นี้
      const changeStream = db.collection('events').watch([{
        $match: {
          operationType: 'insert',
          'fullDocument.session.id': sessionId,
          'fullDocument.event_type': { $in: ['ssh_command', 'cowrie.command.input'] }
        }
      }]);

      changeStream.on('change', (change: any) => {
        const doc = change.fullDocument;
        const input = doc.raw?.payload?.input ?? doc.activity?.command ?? '';
        if (input) {
          commands.push(input);
          const newCwd = computeCwd(commands);
          controller.enqueue(
            `data: ${JSON.stringify({ type: 'update', cwd: newCwd, lastCmd: input })}\n\n`
          );
        }
      });

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
    }
  });
}
```

### ข้อดี / ข้อเสีย

| ✅ ข้อดี | ⚠️ ข้อเสีย |
|---------|-----------|
| ไม่ต้องแก้ Cowrie | ไม่ 100% accurate (alias, script, subshell) |
| ใช้ข้อมูลที่มีอยู่แล้วใน MongoDB | `cd -` ไม่ track OLDPWD |
| Implement ได้เลย | |
| เหมาะกับทั้ง live และ historical sessions | |

---

## แนวทางที่ 2: MongoDB Change Stream Watch (Real-time Transport Layer)

### หลักการ

ใช้ MongoDB Change Stream watch `events` collection โดยตรงและ push ผ่าน SSE — ใช้ร่วมกับแนวทางที่ 1 เป็น real-time transport layer สำหรับ active sessions

### Architecture

```
Cowrie → Redis Stream → Processor Agent → MongoDB events collection
                                               ↓
                                    Change Stream (watch inserts)
                                               ↓
                              Next.js SSE /api/sessions/[id]/cwd/stream
                                               ↓
                                    CwdTracker Component (browser)
```

### Frontend Component

```typescript
// src/components/dashboard/CwdTracker.tsx
'use client';
import { useEffect, useState } from 'react';

interface CwdState {
  cwd: string;
  lastCmd: string | null;
  commandCount: number;
}

export default function CwdTracker({ sessionId }: { sessionId: string }) {
  const [state, setState] = useState<CwdState>({
    cwd: '/root',
    lastCmd: null,
    commandCount: 0,
  });
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const es = new EventSource(`/api/sessions/${sessionId}/cwd/stream`);

    es.onopen = () => setConnected(true);

    es.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'initial') {
        setState({ cwd: msg.cwd, lastCmd: null, commandCount: msg.commands.length });
      } else if (msg.type === 'update') {
        setState(prev => ({
          cwd: msg.cwd,
          lastCmd: msg.lastCmd,
          commandCount: prev.commandCount + 1,
        }));
      }
    };

    es.onerror = () => setConnected(false);

    return () => es.close();
  }, [sessionId]);

  return (
    <div className="font-mono text-sm bg-[#0d0d10] border border-slate-800 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-2">
        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
        <span className="text-slate-400 text-xs">LIVE CWD TRACKER</span>
        <span className="text-slate-600 text-xs ml-auto">{state.commandCount} cmds</span>
      </div>
      <div className="text-emerald-400">
        root@honeypot:<span className="text-cyan-400">{state.cwd}</span>
        <span className="text-white">$</span>
      </div>
      {state.lastCmd && (
        <div className="text-slate-500 text-xs mt-1">
          last: <span className="text-amber-400">{state.lastCmd}</span>
        </div>
      )}
    </div>
  );
}
```

### ข้อดี / ข้อเสีย

| ✅ ข้อดี | ⚠️ ข้อเสีย |
|---------|-----------|
| True real-time push (ไม่ใช่ polling) | ต้อง manage EventSource lifecycle |
| Low latency | SSE connection limit ต่อ browser |
| ใช้ infrastructure เดิม (เหมือน HardwareMonitor) | |

---

## แนวทางที่ 3: Cowrie Output Plugin (สมบูรณ์ที่สุด)

### หลักการ

เพิ่ม Cowrie plugin ที่ hook เข้า `cowrie.command.input` แล้ว inject field `cwd` จาก Cowrie's internal filesystem state ลง JSON log โดยตรง — ได้ path จริงเสมอ ไม่ต้อง simulate

### ตัวอย่าง Cowrie Plugin

```python
# cowrie/output/cwd_tracker.py
from cowrie.core import output

class Output(output.Output):
    """
    Inject current working directory into command events.
    """

    def start(self):
        pass

    def stop(self):
        pass

    def write(self, event):
        if event['eventid'] in ('cowrie.command.input', 'cowrie.command.success', 'cowrie.command.failed'):
            protocol = event.get('_protocol')
            if protocol and hasattr(protocol, 'cwd'):
                event['cwd'] = protocol.cwd
        return event
```

### วิธีเปิดใช้งาน

เพิ่มใน `cowrie.cfg`:
```ini
[output_cwd_tracker]
enabled = true
```

### ผลลัพธ์ที่ได้ใน MongoDB

```json
{
  "event_type": "cowrie.command.input",
  "raw": {
    "payload": {
      "input": "ls -la",
      "cwd": "/opt/odoo",
      "session": "821841d4faeb"
    }
  }
}
```

### ข้อดี / ข้อเสีย

| ✅ ข้อดี | ⚠️ ข้อเสีย |
|---------|-----------|
| ได้ path จริง 100% | ต้องแก้ Cowrie source / config |
| รองรับ alias, script, subshell ทั้งหมด | ต้อง restart Cowrie |
| ไม่ต้อง compute ฝั่ง dashboard | ขึ้นกับ Cowrie version |

---

## สรุปเปรียบเทียบ

| | แนวทาง 1 | แนวทาง 2 | แนวทาง 3 |
|--|----------|----------|----------|
| **หลักการ** | Compute จาก cmd history | Change Stream SSE transport | Cowrie plugin |
| **ความถูกต้อง** | ~90% | ~90% | 100% |
| **Real-time** | ✅ | ✅ | ✅ |
| **แก้ Cowrie** | ❌ | ❌ | ✅ |
| **ความยาก** | ⭐ ง่าย | ⭐ ง่าย | ⭐⭐⭐ ปานกลาง |
| **เหมาะกับ** | Historical + Live | Live sessions | Production ที่ต้องการ accuracy |

---

## แนวทางที่แนะนำ: Hybrid (1 + 2)

ใช้ **แนวทาง 1 เป็น logic** + **แนวทาง 2 เป็น real-time transport layer**

```
MongoDB Change Stream (watch ssh_command inserts)
        ↓
SSE /api/sessions/[sessionId]/cwd/stream
        ↓
computeCwd(commands[])  ← logic จากแนวทาง 1
        ↓
CwdTracker Component (browser)
```

1. **Load initial**: ดึง command history ทั้งหมดของ session → compute CWD ตอนแรก
2. **Stream updates**: Watch MongoDB Change Stream → ทุก `cd` command ใหม่ → recompute → push ผ่าน SSE
3. **แสดงผล**: Terminal-style badge บน active session cards และ threat-intel detail page

### Files ที่ต้อง implement

```
dashboard-v2/src/
├── lib/
│   └── cwdTracker.ts                          # computeCwd() function
├── app/api/sessions/
│   └── [sessionId]/
│       └── cwd/
│           ├── route.ts                       # REST: GET current CWD
│           └── stream/
│               └── route.ts                  # SSE: real-time CWD stream
└── components/dashboard/
    └── CwdTracker.tsx                         # UI component
```
