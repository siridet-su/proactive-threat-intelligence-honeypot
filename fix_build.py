with open('./dashboard-v2/src/components/filesystem/ReplayTransport.tsx', 'r') as f:
    content = f.read()

content = content.replace('pacingMode: "realistic" | "step";', 'pacingMode: string;')
with open('./dashboard-v2/src/components/filesystem/ReplayTransport.tsx', 'w') as f:
    f.write(content)

print("Fixed pacingMode type")
