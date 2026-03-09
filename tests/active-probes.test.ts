import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SQLiProbeTool } from '../tools/sqli-probe';
import { XSSProbeTool } from '../tools/xss-probe';
import { PayloadAgent } from '../agents/payload-agent';
import express from 'express';
import { Server } from 'http';

describe('Real Probing Tests with Local Server', () => {
    let server: Server;
    let baseUrl: string;

    beforeAll(() => {
        const app = express();
        const port = 4000 + Math.floor(Math.random() * 1000);
        baseUrl = `http://127.0.0.1:${port}`;

        // Vulnerable SQLi Endpoint
        app.get('/api/search', (req, res) => {
            const id = req.query.id as string;
            if (id && (id.includes("'") || id.includes('--'))) {
                return res.status(500).send("Database error: SQL syntax error near '' or '1'='1'");
            }
            res.send({ status: 'ok', data: [] });
        });

        // Vulnerable XSS Endpoint
        app.get('/api/profile', (req, res) => {
            const q = req.query.q as string;
            res.send(`<html><body><h1>Search Results for: ${q}</h1></body></html>`);
        });

        server = app.listen(port, '127.0.0.1');
    });

    afterAll(() => {
        server.close();
    });

    it('SQLiProbeTool should detect real SQLi from local server', async () => {
        const result = await SQLiProbeTool.run({ target: `${baseUrl}/api/search` });
        expect(result.findings.length).toBeGreaterThan(0);
        expect(result.data.vulnerability).toBe('SQL Injection');
        expect(result.requestsMade).toBeGreaterThan(0);
    });

    it('XSSProbeTool should detect real XSS from local server reflection', async () => {
        const result = await XSSProbeTool.run({ target: `${baseUrl}/api/profile` });
        expect(result.findings.length).toBeGreaterThan(0);
        expect(result.data.vulnerability).toBe('Reflected XSS');
        expect(result.requestsMade).toBeGreaterThan(0);
    });
});

describe('PayloadAgent Logic', () => {
    it('should delegate to Orchestrator if no endpoints are discovered', async () => {
        const agent = new PayloadAgent();
        const context: any = { discoveredEndpoints: [] };
        const decision = await agent.decide(context);
        expect(decision.action).toBe('delegate');
        expect(decision.nextAgent).toBe('OrchestratorAgent');
    });

    it('should iterate through tools for each endpoint', async () => {
        const agent = new PayloadAgent();
        const context: any = { discoveredEndpoints: ['/api/v1', '/api/v2'] };

        let decision = await agent.decide(context);
        expect(decision.action).toBe('run_tool');
        expect(decision.tool).toBe('sqli_probe');

        decision = await agent.decide(context);
        expect(decision.tool).toBe('xss_probe');

        // Skip ahead to payload_fuzz (the 6th tool)
        for (let i = 0; i < 3; i++) await agent.decide(context);
        decision = await agent.decide(context);
        expect(decision.tool).toBe('payload_fuzz');
    });
});
