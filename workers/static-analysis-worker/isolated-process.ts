import { executeScanJob } from './worker';

console.log(`[Isolated Worker] Process ${process.pid} started.`);

process.on('message', async (message: any) => {
    if (message.type === 'START_JOB') {
        const { jobId, target, jobType, toolName, toolInput } = message.payload;

        try {
            const result = await executeScanJob(jobId, target, jobType, toolName, toolInput, async (progress, statusText) => {
                process.send?.({
                    type: 'PROGRESS',
                    payload: { progress, statusText }
                });
            });

            process.send?.({
                type: 'COMPLETED',
                payload: result
            });
        } catch (error: any) {
            process.send?.({
                type: 'ERROR',
                payload: { message: error.message, stack: error.stack }
            });
        } finally {
            process.exit(0);
        }
    }
});
