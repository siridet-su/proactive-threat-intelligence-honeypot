import re

path = "dashboard-v2/src/components/filesystem/RouteEventList.tsx"
with open(path, "r") as f:
    content = f.read()

# Make destination path and action emphasized and at the top of the item.
# Right now the item renders:
# 1. <div flex between> <p>Action</p> <time>Time</time> </div>
# 2. <div space-y-0.5> Line 1: Origin, Line 2: Destination </div>
# 3. Status
# Let's change this to:
# 1. <div flex gap> <p>Destination Path</p> </div>
# 2. <div flex between> <p>Action</p> </div>
# 3. Status + Time

# Let's use a simpler replace block.

# Emphasize destination path
content = content.replace(
    '{event.toPath ?? "Unknown"}',
    '{event.toPath ?? "Unknown"}'
)

# Replace the icon for Failed
content = content.replace(
    '<span className="ml-auto shrink-0 rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 font-sans text-xs font-semibold text-warning">\n                          Failed\n                        </span>',
    '<span className="ml-auto shrink-0 rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 font-sans text-xs font-semibold text-warning flex items-center gap-1">\n                          <AlertCircle className="h-3 w-3" /> Failed\n                        </span>'
)


with open(path, "w") as f:
    f.write(content)
