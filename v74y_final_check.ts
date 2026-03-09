import { toolRunner } from './services/tool-runner';
import { ScanContext } from './shared/types/scan-context';
import { ToolInput } from './shared/types/tool';
import * as dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

async function testDiscoveryHonesty() {
    const reachableTarget = 'https://google.com';
    const unreachableTarget = 'http://this-does-not-exist.shipout.test';

    const getContext = async (target: string): Promise<ScanContext> => {
        const { getAdminClient } = await import('./services/database/db');
        const supabase = getAdminClient();
        const jobId = crypto.randomUUID();

        await supabase.from('jobs').insert({
            id: jobId,
            target,
            type: 'url',
            status: 'PENDING'
        } as any);

        return {
            jobId,
            target,
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
            agentsUsed: [],
            stagnationCounter: 0,
            investigationMemory: {},
            attackGraph: { nodes: [], edges: [] },
            telemetry: []
        };
    };

    console.log('\n--- Testing Reachable Target (google.com) ---');
    try {
        const context = await getContext(reachableTarget);
        const { result, telemetry } = await toolRunner.executeTool('http_probe', { target: reachableTarget }, context);
        console.log(`[Google] Success: ${telemetry.success}, Findings: ${result.findings?.length}, Error: ${telemetry.error || 'None'}`);
    } catch (e: any) {
        console.log(`[Google] Caught error: ${e.message}`);
    }

    console.log('\n--- Testing Unreachable Target (invalid) ---');
    try {
        const context = await getContext(unreachableTarget);
        const { result, telemetry } = await toolRunner.executeTool('http_probe', { target: unreachableTarget }, context);
        console.log(`[Invalid] Success: ${telemetry.success}, Findings: ${result.findings?.length}, Error: ${telemetry.error || 'None'}`);
        if (!telemetry.success && !result.findings?.length) {
            console.log('[Invalid] ✅ VERIFIED: Tool correctly reported failure and empty findings.');
        } else {
            console.log('[Invalid] ❌ FAILED: Tool reported success or findings on an unreachable target.');
        }
    } catch (e: any) {
        console.log(`[Invalid] Caught expected error in polling: ${e.message}`);
    }
}

testDiscoveryHonesty().catch(console.error);
