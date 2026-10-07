/**
 * Static display-name fallback for the frozen S1 Model1 label set.
 *
 * Names were copied from the repository's offline ATT&CK Enterprise cache
 * (version 14.1). This is presentation metadata only: it does not validate a
 * prediction, change its authority, or imply that the technique was observed.
 */
const MODEL1_TECHNIQUE_NAMES: Readonly<Record<string, string>> = {
  T1003: "OS Credential Dumping",
  T1005: "Data from Local System",
  T1007: "System Service Discovery",
  T1011: "Exfiltration Over Other Network Medium",
  T1016: "System Network Configuration Discovery",
  T1018: "Remote System Discovery",
  T1021: "Remote Services",
  T1033: "System Owner/User Discovery",
  T1040: "Network Sniffing",
  T1046: "Network Service Discovery",
  T1049: "System Network Connections Discovery",
  T1053: "Scheduled Task/Job",
  T1057: "Process Discovery",
  T1059: "Command and Scripting Interpreter",
  T1068: "Exploitation for Privilege Escalation",
  T1069: "Permission Groups Discovery",
  T1070: "Indicator Removal",
  T1078: "Valid Accounts",
  T1082: "System Information Discovery",
  T1083: "File and Directory Discovery",
  T1098: "Account Manipulation",
  T1105: "Ingress Tool Transfer",
  T1110: "Brute Force",
  T1114: "Email Collection",
  T1125: "Video Capture",
  T1136: "Create Account",
  T1222: "File and Directory Permissions Modification",
  T1518: "Software Discovery",
  T1548: "Abuse Elevation Control Mechanism",
  T1550: "Use Alternate Authentication Material",
  T1552: "Unsecured Credentials",
  T1556: "Modify Authentication Process",
  T1560: "Archive Collected Data",
  T1567: "Exfiltration Over Web Service",
  T1569: "System Services",
  T1570: "Lateral Tool Transfer",
  T1572: "Protocol Tunneling",
  T1654: "Log Enumeration",
};

/** Return a bundled Model1 label name, or undefined when the ID is unknown. */
export function model1TechniqueNameFallback(techniqueId: unknown): string | undefined {
  if (typeof techniqueId !== "string") return undefined;
  const normalized = techniqueId.trim().toUpperCase();
  if (!/^T\d{4}(?:\.\d{3})?$/.test(normalized)) return undefined;
  return MODEL1_TECHNIQUE_NAMES[normalized];
}
