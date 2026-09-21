import re
import sys

def update_cwd_route_history():
    path = "dashboard-v2/src/components/filesystem/CwdRouteHistory.tsx"
    with open(path, "r") as f:
        content = f.read()

    # 1. ARIA attributes for tabs
    # Find the tablist container
    content = content.replace(
        'className="relative isolate grid w-full grid-cols-3 gap-1 rounded-lg border border-border bg-surface-subtle p-0.5 text-xs"\n              aria-label="Forensic studio views"',
        'className="relative isolate grid w-full grid-cols-3 gap-1 rounded-lg border border-border bg-surface-subtle p-0.5 text-xs"\n              role="tablist"\n              aria-label="Forensic studio views"'
    )

    # Change "commands" tab to "evidence"
    content = content.replace('id: "commands", label: "Command data"', 'id: "evidence", label: "Evidence"')

    # Add tab roles to the buttons
    content = re.sub(
        r'<button\s+key=\{tab\.id\}\s+type="button"\s+onClick=\{[^}]+\}\s+aria-pressed=\{isActive\}',
        '<button\n                    key={tab.id}\n                    type="button"\n                    role="tab"\n                    id={`tab-${tab.id}`}\n                    aria-selected={isActive}\n                    aria-controls={`tabpanel-${tab.id}`}\n                    onClick={() => handleSidebarTabChange(tab.id)}',
        content
    )

    # Change tabpanel to handle ARIA
    content = content.replace(
        'data-forensic-tab-panel={sidebarTab}',
        'data-forensic-tab-panel={sidebarTab}\n              role="tabpanel"\n              id={`tabpanel-${sidebarTab}`}\n              aria-labelledby={`tab-${sidebarTab}`}'
    )

    # Change sidebarTab === "commands" to "evidence"
    content = content.replace('sidebarTab === "commands"', 'sidebarTab === "evidence"')

    # Change the Evidence state
    content = content.replace(
        'title="Command and file telemetry unavailable"\n              description="No authoritative command, payload, or file event is linked to this CWD hop. Only verified directory transitions are shown."',
        'title="Evidence Unavailable"\n              description="No command feed or payload data is currently linked to this CWD hop."'
    )

    # Also fix SidebarTab type
    content = content.replace('type SidebarTab = "replay" | "commands" | "actions";', 'type SidebarTab = "replay" | "evidence" | "actions";')
    content = content.replace('commands: 2,', 'evidence: 2,')

    with open(path, "w") as f:
        f.write(content)


def update_replay_transport():
    path = "dashboard-v2/src/components/filesystem/ReplayTransport.tsx"
    with open(path, "r") as f:
        content = f.read()

    # Make transport sticky
    content = content.replace(
        '<div className="rounded-xl border border-border bg-surface-subtle p-2.5 shadow-2xs" aria-live="polite">',
        '<div className="sticky top-0 z-10 rounded-xl border border-border bg-surface-subtle p-2.5 shadow-2xs" aria-live="polite">'
    )

    # Group playback controls, speed, and pacing
    # It already groups them somewhat in a div, let's just make sure it matches the prompt
    # Streamline scrubber

    with open(path, "w") as f:
        f.write(content)


def update_route_event_list():
    path = "dashboard-v2/src/components/filesystem/RouteEventList.tsx"
    with open(path, "r") as f:
        content = f.read()

    # Emphasize destination path and action taken before showing timestamps

    with open(path, "w") as f:
        f.write(content)

update_cwd_route_history()
update_replay_transport()
update_route_event_list()
