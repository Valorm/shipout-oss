import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OrchestratorAgent } from '../agents/orchestrator-agent';
import { ScanContext } from '../shared/types/scan-context';

// Mock Gemini
const mockGenerateContent = vi.fn();
vi.mock('@google/generative-ai', () => {
    return {
        GoogleGenerativeAI: vi.fn().mockImplementation(function () {
            return {
                getGenerativeModel: vi.fn().mockReturnValue({
                    generateContent: mockGenerateContent
                })
            };
        })
    };
});

describe('OrchestratorAgent', () => {
    let agent: OrchestratorAgent;
    let mockContext: ScanContext;

    beforeEach(() => {
        process.env.GEMINI_API_KEY = 'test-key';
        agent = new OrchestratorAgent();
        mockContext = {
            jobId: 'test-job',
            target: 'https://example.com',
            jobType: 'url',
            state: 'investigating',
            phase: 'reconnaissance',
            toolsUsed: 0,
            requestsMade: 0,
            startTime: Date.now(),
            discoveredPages: [],
            discoveredEndpoints: [],
            headers: {},
            technologies: [],
            vulnerabilities: [],
            detectedSecrets: [],
            attackGraph: { nodes: [], edges: [] },
            telemetry: []
        };
        mockGenerateContent.mockClear();
    });

    it('should delegate to ReconAgent when mapping is incomplete', async () => {
        mockGenerateContent.mockResolvedValue({
            response: {
                text: () => JSON.stringify({
                    action: 'delegate',
                    nextAgent: 'ReconAgent',
                    reasoning: 'Surface mapping needed'
                }),
                usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, totalTokenCount: 15 }
            }
        });

        const decision = await agent.decide(mockContext);

        expect(decision.action).toBe('delegate');
        expect(decision.nextAgent).toBe('ReconAgent');
        expect(decision.reasoning).toBe('Surface mapping needed');
        expect(decision.tokens?.total).toBe(15);
    });

    it('should stop when no API key is present', async () => {
        delete process.env.GEMINI_API_KEY;
        const agentNoKey = new OrchestratorAgent(); // Re-instantiate to check env

        const decision = await agentNoKey.decide(mockContext);

        expect(decision.action).toBe('stop');
        expect(decision.reasoning).toContain('Missing API key');
    });

    it('should handle LLM failure gracefully', async () => {
        mockGenerateContent.mockRejectedValue(new Error('API error'));

        const decision = await agent.decide(mockContext);

        expect(decision.action).toBe('stop');
        expect(decision.reasoning).toContain('LLM failed');
    });
});
