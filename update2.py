import re

path = "dashboard-v2/src/components/filesystem/RouteEventList.tsx"
with open(path, "r") as f:
    content = f.read()

# Swap destination path and action with timestamps
# The structure is:
# <div className="flex items-center justify-between gap-1.5 min-w-0">
#   <p className="truncate font-medium text-xs text-text min-w-0">
# ...
#   </p>
#   <time ...>
# ...
# </div>

# We can make it:
# 1. Action + Destination
# 2. Origin
# 3. Time + Status

# It might be too complicated to rewrite via script. Let me just replace the whole RouteEventList.tsx using `cat` or write to a new file and `mv`.
