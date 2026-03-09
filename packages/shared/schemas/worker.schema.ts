export type WorkerStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'BLOCKED';

export interface ScanJob {
  jobId: string;
  target: string;
  type: 'url' | 'repo';
  queuedAt: string;
}

export interface InvestigationStep {
  stepIndex: number;
  timestamp: string;
  reasoning: string;
  toolsExecuted: string[];
  keyFindings: string[];
}

export interface WorkerResult {
  jobId: string;
  status: WorkerStatus;
  progress?: number;
  statusText?: string;
  score: number | null;
  confidence?: number;
  coverage?: {
    pages?: number;
    endpoints?: number;
    forms?: number;
    headers?: number;
    scripts?: number;
  };
  checksCompleted?: number;
  totalChecks?: number;
  criticalIssues: string[];
  warnings: string[];
  fixes: { file?: string; description: string; codeSnippet?: string }[];
  riskCategories: string[];
  checklist: { id: string; name: string; status: 'PASS' | 'WARN' | 'FAIL' | 'UNKNOWN'; reason?: string }[];
  investigationSteps?: InvestigationStep[];
  completedAt: string;
  toolResult?: any;
}

