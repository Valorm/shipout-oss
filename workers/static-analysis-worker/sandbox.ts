import { WorkerLimitsPolicy } from './limits.policy';
import { fork } from 'child_process';
import path from 'path';
import os from 'os';

export interface SandboxInstance {
  runJob: (jobId: string, target: string, jobType: 'url' | 'repo', onProgress: (progress: number, statusText: string) => Promise<void>) => Promise<any>;
  destroy: () => void;
}

export function initializeSandbox(jobId: string): SandboxInstance {
  console.log(`[Sandbox] Provisioning isolated process for job ${jobId}...`);

  return {
    runJob: async (jobId, target, jobType, onProgress) => {
      // Filter sensitive environment variables (Isolation)
      // Allowlist only what's needed for the worker to function
      const safeEnv = {
        GEMINI_API_KEY: process.env.GEMINI_API_KEY,
        NODE_ENV: process.env.NODE_ENV,
        PATH: process.env.PATH, // Needed for some tools if they are in the path
      };

      const workerPath = path.resolve(__dirname, 'isolated-process.ts');

      // Restrict outbound network using Node's permission model natively.
      // - Allow Gemini API.
      // - If jobType is 'repo', only allow github.com and api.github.com.
      // - If jobType is 'url', allow the explicit URL hostname and strictly nothing else.
      let allowedNetHost = 'generativelanguage.googleapis.com';
      if (jobType === 'repo') {
        allowedNetHost += ',github.com,api.github.com,raw.githubusercontent.com';
      } else {
        try {
          const targetUrl = new URL(target.startsWith('http') ? target : `https://${target}`);
          allowedNetHost += `,${targetUrl.hostname}`;
        } catch {
          // If unparseable, we let the internal validation catch it but do not open extra net holes
        }
      }

      return new Promise((resolve, reject) => {
        // Fork a child process to run the scan
        const child = fork(workerPath, [], {
          env: safeEnv,
          execArgv: [
            '--permission',
            '--allow-fs-read=*',
            `--allow-fs-write=/tmp,${os.tmpdir()}`,
            `--allow-net=${allowedNetHost}`,
            '--allow-child-process',
            `--max-old-space-size=${WorkerLimitsPolicy.MAX_RAM_MB}`,
            '-r', 'ts-node/register'
          ],
          timeout: WorkerLimitsPolicy.TIMEOUT_SECONDS * 1000
        });

        child.on('message', (message: any) => {
          if (message.type === 'PROGRESS') {
            onProgress(message.payload.progress, message.payload.statusText).catch(console.error);
          } else if (message.type === 'COMPLETED') {
            resolve(message.payload);
          } else if (message.type === 'ERROR') {
            reject(new Error(message.payload.message));
          }
        });

        child.on('error', (err) => {
          reject(err);
        });

        child.on('exit', (code) => {
          if (code !== 0) {
            reject(new Error(`Worker process exited with code ${code}`));
          }
        });

        // Start the job in the child process
        child.send({
          type: 'START_JOB',
          payload: { jobId, target, jobType }
        });
      });
    },
    destroy: () => {
      console.log(`[Sandbox] Cleaning up resources for job ${jobId}.`);
    }
  };
}
