with open('./dashboard-v2/src/components/filesystem/ReplayTransport.tsx', 'r') as f:
    content = f.read()

content = content.replace(
    'replayTimeline: {\n    minValue: number;\n    maxValue: number;\n    value: number;\n    timingLabel: string;\n    durationLabel: string;\n  };',
    'replayTimeline: import("./useAuditReplay").ReplayTimeline;'
)

with open('./dashboard-v2/src/components/filesystem/ReplayTransport.tsx', 'w') as f:
    f.write(content)

with open('./dashboard-v2/src/components/filesystem/RouteEventList.tsx', 'r') as f:
    content = f.read()

content = content.replace(
    'replayTimeline: {\n    durationScope: string;\n    durationLabel: string;\n  };',
    'replayTimeline: import("./useAuditReplay").ReplayTimeline;'
)

with open('./dashboard-v2/src/components/filesystem/RouteEventList.tsx', 'w') as f:
    f.write(content)
