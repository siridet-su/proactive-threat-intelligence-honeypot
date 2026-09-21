import re

def fix_cwd_route_history():
    with open('./dashboard-v2/src/components/filesystem/CwdRouteHistory.tsx', 'r') as f:
        content = f.read()

    # Remove unused icons from lucide-react
    unused_icons = ['AlertCircle,', 'AlertTriangle,', 'ChevronLeft,', 'ChevronRight,', 'Clock,', 'CornerDownRight,', 'FastForward,', 'Pause,', 'Play,', 'Plus,', 'RefreshCw,', 'Rewind,']
    for icon in unused_icons:
        content = re.sub(r'\s*' + icon, '', content)

    # Remove unused functions from filesystemUtils
    unused_utils = ['actionLabel,', 'formatFromPath,', 'isInitialSshEntry,', 'mapReplayTimelineValueToIndex,', 'statusLabel,']
    for util in unused_utils:
        content = re.sub(r'\s*' + util, '', content)

    with open('./dashboard-v2/src/components/filesystem/CwdRouteHistory.tsx', 'w') as f:
        f.write(content)

def fix_replay_transport():
    with open('./dashboard-v2/src/components/filesystem/ReplayTransport.tsx', 'r') as f:
        content = f.read()

    content = content.replace('AlertCircle, ', '')
    with open('./dashboard-v2/src/components/filesystem/ReplayTransport.tsx', 'w') as f:
        f.write(content)

def fix_route_event_list():
    with open('./dashboard-v2/src/components/filesystem/RouteEventList.tsx', 'r') as f:
        content = f.read()

    content = content.replace('import type { RefObject } from "react";\n', '')
    with open('./dashboard-v2/src/components/filesystem/RouteEventList.tsx', 'w') as f:
        f.write(content)

fix_cwd_route_history()
fix_replay_transport()
fix_route_event_list()
print("Fixed lint issues.")
