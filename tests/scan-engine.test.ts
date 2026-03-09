import { describe, it, expect, vi, beforeEach } from 'vitest';

const runInvestigateLoop = vi.fn();
const registerAgent = vi.fn();

vi.mock('../services/agent-planner', () => ({
  AgentPlanner: class {
    registerAgent = registerAgent;
    runInvestigateLoop = runInvestigateLoop;
  }
}));

const generateReport = vi.fn();
vi.mock('../services/report-service/engine', () => ({
  ReportService: {
    generateReport
  }
}));

const updateEq = vi.fn().mockResolvedValue({ error: null });
const update = vi.fn().mockReturnValue({ eq: updateEq });
vi.mock('../services/database/db', () => ({
  getAdminClient: vi.fn().mockReturnValue({
    from: vi.fn().mockReturnValue({ update })
  })
}));

import { ScanEngine } from '../engine/scan-engine';

describe('ScanEngine synthesizer routing', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    runInvestigateLoop.mockResolvedValue({
      jobId: 'job-1',
      target: 'https://example.com',
      jobType: 'url',
      state: 'analyzing',
      phase: 'verification',
      toolsUsed: 2,
      requestsMade: 10,
      startTime: Date.now(),
      discoveredPages: ['/'],
      discoveredEndpoints: ['/api'],
      headers: {},
      technologies: [],
      vulnerabilities: [],
      detectedSecrets: [],
      agentsUsed: ['OrchestratorAgent', 'ReconAgent'],
      stagnationCounter: 0,
      investigationMemory: {},
      attackGraph: { nodes: [], edges: [] },
      telemetry: []
    });

    generateReport.mockResolvedValue({
      score: 80,
      confidence: 0.9,
      criticalIssues: [],
      warnings: [],
      fixes: [],
      riskCategories: [],
      checklist: [],
      tokens: { prompt: 10, completion: 20, total: 30 }
    });
  });

  it('adds SynthesizerAgent and runs reporting after investigation loop exits', async () => {
    const engine = new ScanEngine();
    const result = await engine.startScan('job-1', 'https://example.com', 'url');

    expect(runInvestigateLoop).toHaveBeenCalledTimes(1);
    expect(generateReport).toHaveBeenCalledTimes(1);
    expect(result.state).toBe('completed');
    expect(result.agentsUsed).toContain('SynthesizerAgent');
  });
});
