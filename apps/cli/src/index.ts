#!/usr/bin/env node
// Silence environment noise before any imports
process.env.DOTENV_CONFIG_SILENT = 'true';
process.env.DOTENV_SILENT = 'true';
process.env.DOTENVX_SILENT = 'true';
process.env.DOTENV_TIP = 'false';
process.env.DOTENVX_TIP = 'false';
try {
    if (require('fs').existsSync('.env')) {
        require('dotenv').config({ silent: true });
    }
} catch (e) {
    // ignore
}

import { AgentPlanner } from '../../../core/engine/planner';
import { OrchestratorAgent } from '../../../core/agents/orchestrator-agent';
import { ReconAgent } from '../../../core/agents/recon-agent';
import { WebSecurityAgent } from '../../../core/agents/web-security-agent';
import { SecretsDiscoveryAgent } from '../../../core/agents/secrets-discovery-agent';
import { DataLeakAgent } from '../../../core/agents/data-leak-agent';
import { FormAnalysisAgent } from '../../../core/agents/form-analysis-agent';
import { DependencyAgent } from '../../../core/agents/dependency-agent';
import { PayloadAgent } from '../../../core/agents/payload-agent';
import { VerificationAgent } from '../../../core/agents/verification-agent';
import { ExploitSimulationAgent } from '../../../core/agents/exploit-simulation-agent';
import { ReportAgent } from '../../../core/agents/report-agent';
import { SurfaceExpansionAgent } from '../../../core/agents/surface-expansion-agent';
import { ScanContext } from '../../../packages/shared/types/scan-context';
import { availableTools } from '../../../core/tools';
import * as dotenv from 'dotenv';
import { randomUUID } from 'crypto';
import { cliLogger } from '../../../core/engine/cli-logger';
import { LocalExecutor } from '../../../core/engine/local-executor';
import * as fs from 'fs';
import { ConfigManager } from '../../../core/engine/config';
import * as readline from 'readline';

if (fs.existsSync('.env')) {
    dotenv.config({ path: '.env' });
}

const toolExecutor = new LocalExecutor();


import { runDoctor } from './doctor';

async function main() {
    const args = process.argv.slice(2);
    const command = args[0];
    const isDebug = args.includes('--debug');
    const isJson = args.includes('--json');

    if (args.includes('--version') || args.includes('-v')) {
        console.log(`Shipout Beta v0.1.10`);
        return;
    }

    // Resolve API Key
    const apiKeyFlag = args.find(a => a.startsWith('--api-key='))?.split('=')[1];
    const apiKey = ConfigManager.resolveApiKey(apiKeyFlag);
    if (apiKey) {
        process.env.GEMINI_API_KEY = apiKey;
    }

    if (command === 'setup') {
        await runSetup();
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
        // Check for API Key before scanning
        if (!process.env.GEMINI_API_KEY) {
            console.log('❌ Gemini API key not found.\n');
            console.log('Shipout requires an AI model to run autonomous scans.');
            console.log('Create one here: https://aistudio.google.com/app/apikey\n');

            const wantSetup = await promptQuestion('Would you like to set it up now? (y/n): ');
            if (wantSetup.toLowerCase() === 'y') {
                await runSetup();
                // After setup, the key should be in process.env
            } else {
                console.log('Please set GEMINI_API_KEY in your environment or use --api-key flag.');
                process.exit(1);
            }
        }

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
  shipout setup         Configure your Gemini API key
  shipout doctor        Check your environment for readiness
  shipout --version     Show version
  shipout --help        Show this message

Arguments:
  target                A URL or a path to a file containing a list of URLs

Options:
  --api-key=<key>       Directly provide the Gemini API key
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
    planner.registerAgent(new SecretsDiscoveryAgent());
    planner.registerAgent(new DataLeakAgent());
    planner.registerAgent(new FormAnalysisAgent());
    planner.registerAgent(new DependencyAgent());
    planner.registerAgent(new PayloadAgent());
    planner.registerAgent(new VerificationAgent());
    planner.registerAgent(new ExploitSimulationAgent());
    planner.registerAgent(new ReportAgent());

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

async function promptQuestion(query: string): Promise<string> {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    return new Promise(resolve => rl.question(query, ans => {
        rl.close();
        resolve(ans);
    }));
}

async function runSetup() {
    console.log('\n🚀 Welcome to Shipout Setup\n');
    console.log('Shipout requires an AI model to run autonomous scans.');
    console.log('Create a free Gemini API key here: https://aistudio.google.com/app/apikey\n');

    const apiKey = await promptQuestion('Paste your Gemini API key: ');

    if (!apiKey || apiKey.length < 20) {
        console.error('❌ Invalid API key provided.');
        return;
    }

    await ConfigManager.saveConfig({ gemini_api_key: apiKey });
    process.env.GEMINI_API_KEY = apiKey;

    console.log(`\n✅ API key saved to: ${ConfigManager.getConfigPath()}`);
    console.log('You can now run scans without any extra configuration!\n');
}

main();
