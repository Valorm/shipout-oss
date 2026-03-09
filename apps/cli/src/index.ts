// Silence environment noise before any imports
process.env.DOTENV_CONFIG_SILENT = 'true';
try {
    require('dotenv').config({ silent: true });
} catch (e) {
    // ignore
}

import { AgentPlanner } from '@core/engine/planner';
import { OrchestratorAgent } from '@core/agents/orchestrator-agent';
import { ReconAgent } from '@core/agents/recon-agent';
import { WebSecurityAgent } from '@core/agents/web-security-agent';
import { SecretsAgent } from '@core/agents/secrets-agent';
import { DependencyAgent } from '@core/agents/dependency-agent';
import { PayloadAgent } from '@core/agents/payload-agent';
import { VerifyAgent } from '@core/agents/verify-agent';
import { SurfaceExpansionAgent } from '@core/agents/surface-expansion-agent';
import { ScanContext } from '@shared/types/scan-context';
import { availableTools } from '@core/tools';
import * as dotenv from 'dotenv';
import { randomUUID } from 'crypto';
import { cliLogger } from '@core/engine/cli-logger';
import { LocalExecutor } from '@core/engine/local-executor';
import * as fs from 'fs';

dotenv.config({ path: '.env' });

const toolExecutor = new LocalExecutor();


import { runDoctor } from './doctor';

async function main() {
    const args = process.argv.slice(2);
    const command = args[0];
    const isDebug = args.includes('--debug');
    const isJson = args.includes('--json');

    if (args.includes('--version') || args.includes('-v')) {
        const pkg = require('../package.json');
        console.log(`Shipout CLI v${pkg.version}`);
        return;
    }

    if (args.includes('--help') || args.includes('-h') || command === 'help' || !command) {
        showHelp();
        return;
    }

    if (command === 'doctor') {
        await runDoctor();
        return;
    }

    if (command === 'scan') {
        const target = args[1];
        if (!target) {
            console.error('❌ Error: scan requires a target URL or a file containing URLs.');
            console.log('Usage: shipout scan <url|file> [--debug] [--json]');
            process.exit(1);
        }

        let targets: string[] = [];
        if (fs.existsSync(target)) {
            const content = fs.readFileSync(target, 'utf-8');
            targets = content.split('\n').map(line => line.trim()).filter(line => line.length > 0);
        } else {
            targets = [target];
        }

        const results = [];
        for (const t of targets) {
            const context = await runLiveScan(t, isDebug, isJson);
            if (context) results.push(context);
        }

        if (isJson) {
            console.log(JSON.stringify(results, null, 2));
        }
    } else if (command.startsWith('http')) {
        await runLiveScan(command, isDebug, isJson);
    } else {
        console.error(`❌ Unknown command: ${command}`);
        showHelp();
        process.exit(1);
    }
}

function showHelp() {
    console.log(`
Shipout CLI - Autonomous Security Engine

Usage:
  shipout scan <target> Run an autonomous security scan
  shipout doctor        Check your environment for readiness
  shipout --version     Show version
  shipout --help        Show this message

Arguments:
  target                A URL or a path to a file containing a list of URLs

Options:
  --json                Output results in JSON format
  --debug               Enable verbose logging
`);
}

async function runLiveScan(target: string, isDebug: boolean, isJson: boolean): Promise<ScanContext | null> {
    cliLogger.setDebug(isDebug);
    cliLogger.setSilent(isJson);
    cliLogger.start(target, 25);

    const planner = new AgentPlanner({
        maxTools: 25,
        maxRequests: 200,
        maxTime: 300000, // 5 minute timeout for live runs
        debug: isDebug
    }, toolExecutor, cliLogger);

    const orchestrator = new OrchestratorAgent();
    planner.registerAgent(new ReconAgent());
    planner.registerAgent(new SurfaceExpansionAgent());
    planner.registerAgent(new WebSecurityAgent());
    planner.registerAgent(new SecretsAgent());
    planner.registerAgent(new DependencyAgent());
    planner.registerAgent(new VerifyAgent());

    const context: ScanContext = {
        jobId: randomUUID(),
        target: target,
        jobType: 'url',
        state: 'initializing',
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
        agentsUsed: [],
        stagnationCounter: 0,
        investigationMemory: {},
        attackGraph: { nodes: [], edges: [] },
        telemetry: []
    };

    try {
        const finalContext = await planner.runInvestigateLoop(orchestrator, context);
        cliLogger.logSummary(finalContext);
        return finalContext;
    } catch (e: any) {
        if (!isJson) {
            console.error(`\n❌ Scan Failed for ${target}: ${e.message}`);
        }
        return null;
    }
}

main();
