import { validateTargetUrl } from '../../packages/shared/validation/ssrf-protection';
import { enqueueJob } from '../job-queue/producer';
import { ServiceIdentity, verifyServiceIdentity, generateServiceIdentity } from '../../packages/shared/security-utils/service-identity';
import { EmergencyStopPolicy } from '../../packages/shared/policies/emergency-stop.policy';
import { ScanLimitsPolicy } from '../../packages/shared/policies/scan-limits.policy';
import { getAdminClient } from '../database/db';

export async function forwardToGateway(target: string, type: 'url' | 'repo', callerIdentity: ServiceIdentity, userId?: string, scheduledInterval?: string): Promise<string> {
  // 0. Verify Caller Identity (Zero Trust)
  if (!verifyServiceIdentity(callerIdentity, 'api-route')) {
    throw new Error('Gateway Rejection: Unauthorized internal service call. Invalid identity signature.');
  }

  // 1. Emergency Stop Policy enforcement
  if (EmergencyStopPolicy.GLOBAL_SCAN_DISABLE) {
    throw new Error('Gateway Rejection: The security audit engine is temporarily disabled for maintenance.');
  }
  if (EmergencyStopPolicy.DISABLED_WORKER_TYPES.includes(type)) {
    throw new Error(`Gateway Rejection: Audit type '${type}' is temporarily disabled.`);
  }

  // 1.5 Scan Limits Enforcement (Quota/Concurrent Scans)
  if (userId) {
    const client = getAdminClient();
    const { count, error } = await client
      .from('jobs')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', userId)
      .in('status', ['PENDING', 'RUNNING']);

    if (!error && count !== null && count >= ScanLimitsPolicy.MAX_CONCURRENT_SCANS_PER_USER) {
      throw new Error(`Gateway Rejection: Maximum concurrent scans (${ScanLimitsPolicy.MAX_CONCURRENT_SCANS_PER_USER}) reached. Please wait for active scans to finish.`);
    }
  }

  // 2. Validate Input at the Boundary
  if (type === 'url') {
    const validation = await validateTargetUrl(target);
    if (!validation.valid) {
      throw new Error(`Gateway Rejection: ${validation.error}`);
    }
  } else if (type === 'repo') {
    // Allow owner/repo or full Git URLs, extracting the owner/repo part
    // Matches: owner/repo, https://github.com/owner/repo, git@github.com:owner/repo.git
    const repoPattern = /([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git|\/)?$/;
    const match = target.match(repoPattern);
    if (!match) {
      throw new Error(`Gateway Rejection: Invalid repository format. Use owner/repo or a valid repository URL.`);
    }
    // Normalize target to just owner/repo
    target = `${match[1]}/${match[2]}`;
  }

  // 3. The API Edge Route (`app/api-edge/scan/route.ts`) already handles user authentication and sets `userId`.
  // If `userId` is required for repository scans, we can enforce it here as an additional layer.
  if (type === 'repo' && !userId) {
    throw new Error('Gateway Rejection: Repository scans require an authenticated user.');
  }

  // Generate identity for the orchestrator to pass to the queue
  const orchestratorIdentity = generateServiceIdentity('orchestrator');

  // 3. Forward to Queue
  const jobId = await enqueueJob({ target, type, scheduledInterval }, orchestratorIdentity, userId);

  return jobId;
}
