import { QueueMessage } from './types';
import { QueuePolicy } from './queue.policy';
import { getAdminClient } from '../database/db';
import { generateServiceIdentity } from '../../packages/shared/security-utils/service-identity';
import { spawn } from 'child_process';

const FLY_API_TOKEN = process.env.FLY_API_TOKEN;
const FLY_APP_NAME = process.env.FLY_APP_NAME;
const WORKER_IMAGE = process.env.WORKER_IMAGE || 'registry.fly.io/shipout-worker:latest';
const BASE_URL = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
const POLL_INTERVAL_MS = Number(process.env.JOB_QUEUE_POLL_INTERVAL_MS || 1000);

const missingFlyConfig = [
  ['FLY_API_TOKEN', FLY_API_TOKEN],
  ['FLY_APP_NAME', FLY_APP_NAME]
].filter(([, value]) => !value).map(([name]) => name);

let isPolling = false;
let hasLoggedLocalFlyFallback = false;

async function safePollQueueUntilEmpty() {
  if (isPolling) return;
  isPolling = true;
  try {
    await pollQueueUntilEmpty();
  } finally {
    isPolling = false;
  }
}

async function dispatchToFlyMachine(toolJob: any, scanJob: any) {
  const identity = generateServiceIdentity('worker');

  const workerEnv: any = {
    ...process.env,
    JOB_ID: scanJob.id,
    TARGET: scanJob.target,
    JOB_TYPE: scanJob.type,
    TOOL_NAME: toolJob.tool_name,
    TOOL_INPUT: JSON.stringify(toolJob.input_payload || {}),
    TOOL_JOB_ID: toolJob.id,
    GEMINI_API_KEY: process.env.GEMINI_API_KEY,
    CALLBACK_URL: `${BASE_URL}/api/worker/callback`,
    JOB_IDENTITY: JSON.stringify(identity)
  };

  if (missingFlyConfig.length > 0) {
    throw new Error(`Fly.io dispatch disabled (missing: ${missingFlyConfig.join(', ')}). Local tool execution is disabled for consistency.`);
  }

  const response = await fetch(`https://api.machines.dev/v1/apps/${FLY_APP_NAME}/machines`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${FLY_API_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      region: process.env.FLY_REGION || 'iad',
      config: {
        image: WORKER_IMAGE,
        env: workerEnv,
        auto_destroy: true,
        restart: { policy: 'no' },
        guest: {
          cpu_kind: 'shared',
          cpus: 1,
          memory_mb: 512
        }
      }
    })
  });

  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`Fly.io Machine creation failed: ${response.status} ${errorData}`);
  }

  const data = await response.json();
  console.log(`[JobQueue Worker] Dispatched tool job ${toolJob.id} to Fly Machine ${data.id}`);
  return data;
}

import express from 'express';

export async function startWorker() {
  console.log('[JobQueue Worker] Starting worker with ScanEngine mode...');

  // Simple health check server for Fly.io
  const app = express();
  const port = process.env.PORT || 3000;

  app.get('/health', (req, res) => {
    res.send('OK');
  });

  app.listen(Number(port), '0.0.0.0', () => {
    console.log(`[JobQueue Worker] Health server listening on 0.0.0.0:${port}`);
    console.log(`[JobQueue Worker] Worker registered and READY to process jobs.`);
  });

  const supabase = getAdminClient();

  // Initial poll to catch missed jobs
  await safePollQueueUntilEmpty();

  // Periodic poll to process delayed retries/scheduled runs when no new INSERT event occurs
  setInterval(() => {
    safePollQueueUntilEmpty().catch(err => console.error('[JobQueue Worker] Error in periodic polling:', err));
  }, POLL_INTERVAL_MS);

  // Listen for new jobs instantly
  supabase
    .channel('jobs_queue')
    .on('postgres_changes',
      {
        event: 'INSERT',
        schema: 'public',
        table: 'jobs',
        filter: 'status=eq.PENDING'
      },
      (payload) => {
        console.log('[JobQueue Worker] New scan job detected via Realtime:', payload.new.id);
        safePollQueueUntilEmpty().catch(err => console.error('[JobQueue Worker] Error processing realtime job:', err));
      }
    )
    .on('postgres_changes',
      {
        event: 'INSERT',
        schema: 'public',
        table: 'tool_jobs',
        filter: 'status=eq.PENDING'
      },
      (payload) => {
        console.log('[JobQueue Worker] New tool job detected via Realtime:', payload.new.id);
        safePollQueueUntilEmpty().catch(err => console.error('[JobQueue Worker] Error processing realtime job:', err));
      }
    )
    .subscribe((status) => {
      console.log(`[JobQueue Worker] Supabase realtime subscription status: ${status}`);
    });
}

async function pollQueueUntilEmpty() {
  let hasJobs = true;
  while (hasJobs) {
    try {
      hasJobs = await pollAndProcess();
    } catch (err) {
      console.error('[JobQueue Worker] Error in polling loop:', err);
      hasJobs = false;
    }
  }
}

async function pollAndProcess() {
  const supabase = getAdminClient();

  // 1. Try to claim a tool job first (higher priority, these unblock active scans)
  const { data: toolJobs, error: toolError } = await supabase.rpc('claim_next_tool_job') as { data: any[] | null; error: any };

  if (toolJobs && toolJobs.length > 0) {
    const toolJob = toolJobs[0];
    console.log(`[JobQueue Worker] Picked up tool job ${toolJob.id} (${toolJob.tool_name})`);

    // Fetch associated scan job for context
    const { data: scanJobRaw } = await supabase.from('jobs').select('*').eq('id', toolJob.scan_job_id).single();
    const scanJob = scanJobRaw as any;

    if (!scanJob) {
      console.error(`[JobQueue Worker] Scan job not found for tool job ${toolJob.id}`);
      await (supabase.from('tool_jobs') as any).update({ status: 'FAILED' }).eq('id', toolJob.id);
      return true; // Still return true so we keep polling
    }

    try {
      await dispatchToFlyMachine(toolJob, scanJob);
    } catch (e: any) {
      console.error(`[JobQueue Worker] Error dispatching tool job ${toolJob.id}:`, e);

      await (supabase.from('tool_jobs') as any).update({
        status: 'FAILED',
      }).eq('id', toolJob.id);

      await (supabase.from('tool_results') as any).upsert({
        tool_job_id: toolJob.id,
        error_message: e.message
      });
    }

    return true;
  }

  // 2. If no tool jobs, try to claim a scan job
  const { data: jobs, error } = await supabase.rpc('claim_next_job') as { data: any[] | null; error: any };

  if (error) {
    console.error('[JobQueue Worker] Error claiming job:', error);
    return false;
  }

  if (!jobs || jobs.length === 0) return false;

  const job = jobs[0];
  console.log(`[JobQueue Worker] Picked up scan job ${job.id} (Target: ${job.target})`);

  // Hand off to ScanEngine completely, without blocking
  // (We use a fire-and-forget promise for the scan engine so the consumer doesn't block)
  // The ScanEngine itself updates the jobs table
  executeScanEngine(job.id, job.target, job.type).catch(e => {
    console.error(`[JobQueue Worker] ScanEngine failed for job ${job.id}:`, e);
  });

  return true;
}

// Background task
async function executeScanEngine(jobId: string, target: string, type: 'url' | 'repo') {
  const { getAdminClient } = await import('../database/db');
  const supabase = getAdminClient();

  try {
    const { scanEngine } = await import('../../core/engine/scan-engine');

    if (type !== 'url' && type !== 'repo') {
      throw new Error(`Invalid job type: ${type}`);
    }

    await (supabase.from('jobs') as any).update({
      status: 'RUNNING',
      status_text: 'Starting AI investigator loop...'
    }).eq('id', jobId);

    await scanEngine.startScan(jobId, target, type);

    // Final report and completion handled by webhook/reporting flow for now
  } catch (e: any) {
    console.error(`[JobQueue Worker] ScanEngine failed for job ${jobId}:`, e);
    await (supabase.from('jobs') as any).update({
      status: 'FAILED',
      status_text: `ScanEngine crashed: ${e.message || 'Unknown error'}`,
      critical_issues: [`Failure: ${e.message || 'Unknown error'}`],
      completed_at: new Date().toISOString()
    }).eq('id', jobId);
  }
}

// Start the worker
startWorker().catch(err => {
  console.error('[JobQueue Worker] Fatal error during startup:', err);
  process.exit(1);
});
