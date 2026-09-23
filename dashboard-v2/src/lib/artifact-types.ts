export const ARTIFACT_INTEL_STATUSES = [
  "known_malicious",
  "no_malicious_detections",
  "unknown_to_provider",
  "pending",
  "disabled",
  "failed",
  "stale",
] as const;

export type ArtifactIntelStatus = (typeof ARTIFACT_INTEL_STATUSES)[number];

export interface ArtifactIntel {
  provider: "virustotal";
  status: ArtifactIntelStatus;
  knownToProvider: boolean | null;
  detectionRatio: string | null;
  malwareFamily: string | null;
  queriedAt: string | null;
  expiresAt: string | null;
}

export interface ArtifactRecord {
  id: string;
  artifactSha256: string;
  hashAlgorithm: "sha256";
  firstSeen: string | null;
  lastSeen: string | null;
  observedFilename: string | null;
  observedUrl: string | null;
  sizeBytes: number | null;
  sourceIps: string[];
  sessionIds: string[];
  evidenceCount: number;
  intel: ArtifactIntel;
  retention: {
    bytesRetained: false;
    mode: "hash_only";
  };
}

export interface ArtifactPage {
  success: true;
  items: ArtifactRecord[];
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
  totalIsApproximate: boolean;
  asOf: string;
  scope: "sha256_observations";
  dataSource: "threat_intel" | "enrichment_records" | "events" | "none";
}
