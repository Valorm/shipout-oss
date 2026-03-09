import { WorkerResult } from "../../packages/shared/schemas/worker.schema";
import { validateTargetUrl } from "../../packages/shared/validation/ssrf-protection";
import { WorkerLimitsPolicy } from "./limits.policy";
import { sanitizeObject } from "../../packages/shared/security-utils/sanitization";
import { metrics } from "../../services/database/metrics";
import { ReportService } from "../../services/report-service/engine";
import { AgentOrchestrator } from "./agent";
import { exec } from 'child_process';
import util from 'util';
import path from 'path';
import os from 'os';
import fs from 'fs';

const execAsync = util.promisify(exec);

export async function executeScanJob(
  jobId: string,
  target: string,
  type: 'url' | 'repo',
  toolName?: string,
  toolInput?: any,
  onProgress?: (progress: number, statusText: string) => Promise<void>
): Promise<WorkerResult> {
  try {
    await onProgress?.(5, "Validating target security policies...");

    // 1. Final SSRF check inside the worker (Defense in Depth)
    if (type === 'url' || toolInput?.target) {
      const validationTarget = toolInput?.target || target;
      const validation = await validateTargetUrl(validationTarget);
      if (!validation.valid) {
        if (process.env.SUPABASE_SERVICE_ROLE_KEY) {
          await metrics.increment('requests_blocked');
        }
        return {
          jobId,
          status: 'BLOCKED',
          score: null,
          criticalIssues: ['SSRF attempt detected by worker.'],
          warnings: [],
          fixes: [],
          riskCategories: [],
          checklist: [],
          completedAt: new Date().toISOString()
        };
      }
    }

    if (toolName && toolInput) {
      // New Sandbox Mode
      const { availableTools } = await import('../../core/tools');

      const tool = availableTools[toolName];
      if (!tool) {
        throw new Error(`Tool ${toolName} is not supported by this sandbox.`);
      }

      console.log(`[Worker] Executing tool ${toolName} for job ${jobId}`);
      const result = await tool.run(toolInput);
      console.log(`[Worker] Tool ${toolName} finished with ${result.findings?.length || 0} findings.`);

      return {
        jobId,
        status: 'COMPLETED',
        progress: 100,
        statusText: "Tool execution complete.",
        score: null, // Tools don't return scores
        criticalIssues: [],
        warnings: [],
        fixes: [],
        riskCategories: [],
        checklist: [],
        completedAt: new Date().toISOString(),
        toolResult: result // Special field for tools
      } as any; // Typecast for now until schema is updated
    } else if (type === 'url') {
      // Fallback or error path if someone submits url type with no tool
      throw new Error(`URL scan requires a tool dispatch from ScanEngine.`);
    } else {
      // For Repositories, keep the existing static clone logic as the agent primarily targets running URLs in this phase
      return await scanRepository(jobId, target, type, onProgress);
    }

  } catch (e: any) {
    console.error("[Worker] Execution failed:", e);

    let userMessage = 'An unexpected error occurred during the scan. Please try again.';
    const errMsg = e.message || '';

    if (errMsg.includes('429') || errMsg.includes('RESOURCE_EXHAUSTED')) {
      userMessage = '⏳ The AI analysis engine is temporarily at capacity.';
    } else if (errMsg.includes('401') || errMsg.includes('403')) {
      userMessage = '🔑 AI engine authentication failed.';
    } else if (errMsg.includes('timeout')) {
      userMessage = '⏱️ The scan took too long to complete. Please try again with a smaller target.';
    }

    return {
      jobId,
      status: 'FAILED',
      score: null,
      criticalIssues: [userMessage, errMsg],
      warnings: [],
      fixes: [],
      riskCategories: [],
      checklist: [],
      completedAt: new Date().toISOString()
    };
  }
}

async function scanRepository(jobId: string, target: string, type: 'url' | 'repo', onProgress?: (p: number, s: string) => Promise<void>): Promise<WorkerResult> {
  // 0. Setup Global Timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), WorkerLimitsPolicy.TIMEOUT_SECONDS * 1000);
  const MAX_DATA_SIZE = 500_000;
  let targetData = "";

  try {
    await onProgress?.(10, `Cloning repository ${target} into tmp...`);
    const [owner, repo] = target.split('/');
    if (!owner || !repo) throw new Error('Invalid repository format. Use owner/repo.');

    const repoUrl = `https://github.com/${owner}/${repo}.git`;
    const cloneDir = path.join(os.tmpdir(), `repo-${jobId}`);

    try {
      await execAsync(`git clone --depth 1 ${repoUrl} ${cloneDir}`, { timeout: 60000 });
    } catch (cloneErr: any) {
      throw new Error(`Git clone failed: ${cloneErr.message}`);
    }

    let totalFilesScanned = 0;
    const findCriticalFiles = (dir: string): string[] => {
      let results: string[] = [];
      if (!fs.existsSync(dir)) return results;
      const list = fs.readdirSync(dir);
      for (let file of list) {
        if (++totalFilesScanned > WorkerLimitsPolicy.MAX_FILE_COUNT) {
          throw new Error(`Repository exceeds maximum file limit of ${WorkerLimitsPolicy.MAX_FILE_COUNT}`);
        }
        const absolutePath = path.resolve(dir, file);
        const stat = fs.statSync(absolutePath);
        if (stat && stat.isDirectory()) {
          if (!file.includes('.git') && !file.includes('node_modules')) {
            results = results.concat(findCriticalFiles(absolutePath));
          }
        } else {
          const lowerPath = file.toLowerCase();
          if (lowerPath.includes('package.json') || lowerPath.includes('.env.example') || lowerPath.includes('middleware.ts') || lowerPath.includes('worker.ts') || lowerPath.includes('route.ts') || lowerPath.includes('db.ts') || lowerPath.includes('.config.')) {
            results.push(absolutePath);
          }
        }
      }
      return results;
    };

    const criticalFiles = findCriticalFiles(cloneDir).slice(0, 10);
    await onProgress?.(40, "Reading critical source files from isolated clone...");

    let fileContents = [];
    let totalRepoSize = 0;
    for (const file of criticalFiles) {
      if (totalRepoSize > MAX_DATA_SIZE) break;
      const content = fs.readFileSync(file, 'utf8');
      totalRepoSize += content.length;
      const relativePath = path.relative(cloneDir, file);
      fileContents.push(`\n--- FILE: ${relativePath} ---\n${content.substring(0, 5000)}`);
    }

    targetData = `Repository Tree:\n${criticalFiles.map(f => path.relative(cloneDir, f)).join('\n')}\n\nSelected File Contents:\n${fileContents.join('\n')}`;

    try {
      fs.rmSync(cloneDir, { recursive: true, force: true });
    } catch (e) {
      console.error('[Worker] Failed to cleanup clone dir:', e);
    }

    const detectedSecrets = scanForSecrets(targetData);
    if (detectedSecrets.length > 0) {
      await onProgress?.(65, `⚠️ Detected ${detectedSecrets.length} potential secrets!`);
    }

    const sanitizedData = sanitizeObject(targetData);

    await onProgress?.(75, "Performing AI-powered security audit...");
    const auditResult = await ReportService.generateReport(target, type, sanitizedData, detectedSecrets);

    return {
      jobId,
      status: 'COMPLETED',
      progress: 100,
      statusText: "Audit complete.",
      ...auditResult,
      completedAt: new Date().toISOString()
    };
  } catch (err: any) {
    if (err.name === 'AbortError') throw new Error('Scan timed out during repository fetch.');
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

function scanForSecrets(data: string): string[] {
  const patterns = [
    { name: 'GitHub Token', regex: /gh[pous]_[a-zA-Z0-9]{36}/g },
    { name: 'AWS Access Key', regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g },
    { name: 'Stripe Secret Key', regex: /sk_(live|test)_[0-9a-zA-Z]{24}/g },
    { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g },
    { name: 'Google API Key', regex: /AIza[0-9A-Za-z-_]{35}/g },
    { name: 'Firebase Config', regex: /apiKey: "AIza[0-9A-Za-z-_]{35}"/g }
  ];

  const found: string[] = [];
  for (const p of patterns) {
    const matches = data.match(p.regex);
    if (matches) {
      matches.forEach(m => {
        const obfuscated = m.substring(0, 4) + '...' + m.substring(m.length - 4);
        found.push(`${p.name}: ${obfuscated}`);
      });
    }
  }
  return [...new Set(found)];
}
