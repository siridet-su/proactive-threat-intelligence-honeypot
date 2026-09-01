export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export interface ThreatEvent {
  id: string;
  timestamp: string;
  sensor: string;
  protocol: string;
  sourceIp: string;
  eventType: string;
  payloadPreview: string;
  severity: RiskLevel;
}

export interface AttackerInfo {
  ip: string;
  country: string;
  asn: string;
  attackCount: number;
  firstSeen: string;
  lastSeen: string;
  mainTechnique: string;
  riskScore: number;
  status: RiskLevel;
  latitude: number;
  longitude: number;
}

export interface AttackTimelineData {
  time: string;
  ssh: number;
  telnet: number;
  http: number;
  ftp: number;
  smb: number;
  portScan: number;
}

export interface AttackTypeBreakdown {
  name: string;
  value: number;
  color: string;
}

export interface ServiceData {
  name: string;
  count: number;
}

export interface CredentialData {
  name: string;
  count: number;
}

export interface AttackerBehavior {
  avgSessionDuration: string;
  commandsPerSession: number;
  topCommands: { command: string; count: number }[];
  fileDownloads: number;
  shellInteractions: number;
}

export interface FingerprintData {
  type: string;
  value: string;
  count: number;
  risk: RiskLevel;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  eventCount: number;
  severity: RiskLevel;
}

export interface SensorHealth {
  name: string;
  status: 'Online' | 'Offline' | 'Degraded';
  uptime: string;
  eventsProcessed: number;
  latency: string;
  lastHeartbeat: string;
}
