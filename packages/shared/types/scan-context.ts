export type ScanState =
  | 'queued'
  | 'initializing'
  | 'investigating'
  | 'analyzing'
  | 'reporting'
  | 'completed'
  | 'failed';

export interface ScanBudget {
  maxTools: number;
  maxRequests: number;
  maxTime: number; // in milliseconds
  debug?: boolean;
}

export interface ToolTelemetry {
  tool: string;
  input: any;
  duration: number; // milliseconds
  requests: number;
  success: boolean;
  result: any;
  error?: string;
  timestamp: string;
  // AI Metrics
  tokens?: {
    prompt: number;
    completion: number;
    total: number;
  };
  cost?: number; // Estimated USD
}

export interface Finding {
  type: string;
  description: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence?: number; // 0.0 to 1.0
  evidence?: any;
  verified?: boolean;
  endpoint?: string;
  parameter?: string;
  payload?: string;
  remediation?: string;
  agent?: string;
}

export type ScanPhase = 'reconnaissance' | 'surface_mapping' | 'vulnerability_analysis' | 'verification';

export interface GraphNode {
  id: string;
  type: 'target' | 'service' | 'endpoint' | 'vulnerability' | 'secret';
  label: string;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  from: string;
  to: string;
  type: 'contains' | 'exposed_at' | 'vulnerable_to' | 'identifies' | 'leads_to';
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ScanContext {
  jobId: string;
  target: string;
  jobType: 'url' | 'repo';

  // State Machine
  state: ScanState;
  phase?: ScanPhase;

  // Budget Tracking
  toolsUsed: number;
  requestsMade: number;
  startTime: number;

  // Discovered Attack Surface
  discoveredPages: string[];
  discoveredEndpoints: string[];
  headers: Record<string, string>;
  technologies: string[];

  // Analysis
  vulnerabilities: Finding[];
  detectedSecrets: string[];

  // Attack Graph (Level 4 Reasoning)
  attackGraph: AttackGraph;

  // Active Plan (Level 4)
  currentPlan?: {
    strategy: string;
    objectives: { id: string; description: string; priority: string; status: string }[];
  };

  // Agents (Level 4 tracking)
  agentsUsed: string[];

  // Telemetry (Investigation Timeline)
  telemetry: ToolTelemetry[];

  // Cumulative Metrics
  totalTokens?: {
    prompt: number;
    completion: number;
    total: number;
  };
  totalCost?: number;
  stagnationCounter: number;
  investigationMemory: Record<string, string[]>;
  targetProfile?: {
    waf?: string;
    framework?: string;
    server?: string;
  };
}
