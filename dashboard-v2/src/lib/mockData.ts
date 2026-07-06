// src/lib/mockData.ts

export const systemStats = {
  attacksPrevented: "1,248,302",
  threatLevel: "Level 4: High",
  systemHealth: "99.98%",
  activeNodes: "14,802"
};

export const incidentLogs = [
  {
    id: "1",
    timestamp: "14:02:44.823",
    severity: "CRITICAL",
    type: "Brute Force Attempt",
    sourceIp: "192.168.1.104",
    status: "Blocked",
  },
  {
    id: "2",
    timestamp: "14:01:12.010",
    severity: "HIGH",
    type: "SQL Injection Pattern",
    sourceIp: "45.23.188.12",
    status: "Quarantined",
  },
  {
    id: "3",
    timestamp: "14:00:05.441",
    severity: "MEDIUM",
    type: "Cognitive Decoy Triggered",
    sourceIp: "10.0.4.155",
    status: "Logged",
  },
  {
    id: "4",
    timestamp: "13:58:32.992",
    severity: "LOW",
    type: "Unauthorized Config Access",
    sourceIp: "Intra-Node-A4",
    status: "Investigating",
  },
];

export const hackerProfiles = {
  "1": { ip: "192.168.44.122", name: "State-Sponsored APT", data: [/* กราฟของ ID 1 */] },
  "2": { ip: "84.21.112.5", name: "Automated Botnet", data: [/* กราฟของ ID 2 */] },
  // ... อื่นๆ
};