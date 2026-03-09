import { QueueMessage, QueuePublishResult } from './types';
import { QueuePolicy } from './queue.policy';
import { ServiceIdentity, verifyServiceIdentity } from '../../packages/shared/security-utils/service-identity';
import { db } from '../database/db';

export async function enqueueJob(payload: Omit<QueueMessage, 'jobId' | 'queuedAt' | 'retryCount'>, callerIdentity: ServiceIdentity, userId?: string): Promise<string> {
  // 0. Verify Caller Identity (Zero Trust)
  // Only the orchestrator is allowed to push jobs to the queue
  if (!verifyServiceIdentity(callerIdentity, 'orchestrator')) {
    throw new Error('Queue Rejection: Unauthorized producer. Only orchestrators can enqueue jobs.');
  }

  const jobId = crypto.randomUUID(); // Supabase expects an actual UUID!

  const message: QueueMessage = {
    jobId,
    target: payload.target,
    type: payload.type,
    queuedAt: new Date().toISOString(),
    retryCount: 0,
    scheduledInterval: payload.scheduledInterval
  };

  // 1. Create the pending job record in the database
  await db.createJob({
    id: jobId,
    user_id: userId,
    target: payload.target,
    type: payload.type,
    status: 'PENDING',
    score: null,
    criticalIssues: [],
    warnings: [],
    fixes: [],
    riskCategories: [],
    checklist: [],
    createdAt: message.queuedAt,
    scheduled_interval: payload.scheduledInterval
  });

  // 2. Publish to queue (In production, this would publish to Kafka/RabbitMQ)
  // For now, the database record itself acts as our queue item.
  console.log(`[JobQueue Producer] Job ${jobId} enqueued in database. Status: PENDING`);

  return jobId;
}
