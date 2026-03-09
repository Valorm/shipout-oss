import { fork } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runHardenedTest() {
    console.log('[Test Runner] Starting hardened sandbox test...');

    const safeEnv = {
        GEMINI_API_KEY: 'test-key',
        NODE_ENV: 'test',
        PATH: process.env.PATH,
    };

    const workerPath = path.resolve(__dirname, 'test-isolated-process.ts');

    return new Promise((resolve, reject) => {
        const child = fork(workerPath, [], {
            env: safeEnv as any,
            execArgv: [
                '--permission',
                '-r', 'ts-node/register'
            ]
        });

        child.on('message', (message: any) => {
            console.log(`[Test Runner] Received from worker:`, JSON.stringify(message, null, 2));
            if (message.type === 'COMPLETED') {
                resolve(message.payload);
            } else if (message.type === 'ERROR') {
                reject(new Error(message.payload.message));
            }
        });

        child.on('error', (err) => {
            console.error('[Test Runner] Child process error:', err);
            reject(err);
        });

        child.on('exit', (code) => {
            console.log(`[Test Runner] Child process exited with code ${code}`);
            if (code !== 0 && code !== null) {
                // We expect non-zero exit if there's a hard error from permission violation
                console.log(`[Test Runner] Worker failed as expected (or crashed).`);
            }
            resolve(null);
        });

        child.send({
            type: 'START_JOB',
            payload: { jobId: 'test-job-123', target: 'example.com', jobType: 'url' }
        });
    });
}

runHardenedTest().then(() => {
    console.log('[Test Runner] Test sequence finished.');
}).catch(err => {
    console.error('[Test Runner] Test failed with error:', err);
});
