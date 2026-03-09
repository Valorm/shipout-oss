import { AgentTool, AgentContext, ToolResult } from '../types';
import * as fs from 'fs';
import * as path from 'path';

export const DependencyScannerTool: AgentTool = {
    name: 'DependencyScanner',
    description: 'Scans repository dependency files (package.json, requirements.txt, etc.) for known outdated or vulnerable packages.',

    shouldRun: (ctx: AgentContext) => {
        return ctx.jobType === 'repo';
    },

    execute: async (ctx: AgentContext, signal: AbortSignal): Promise<ToolResult> => {
        const findings: string[] = [];
        let severity: ToolResult['severity'] = 'LOW';
        const cloneDir = path.join('/tmp', `shipout-job-${ctx.jobId}`);

        try {
            // 1. Node.js (package.json)
            const packageJsonPath = path.join(cloneDir, 'package.json');
            if (fs.existsSync(packageJsonPath)) {
                const pj = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
                const deps = { ...(pj.dependencies || {}), ...(pj.devDependencies || {}) };

                findings.push(`Detected ${Object.keys(deps).length} Node.js dependencies.`);

                // Critical set of high-risk vulnerabilities to look for (Simulated DB check)
                const highRisk = ['lodash', 'axios', 'express', 'moment', 'shelljs'];
                for (const [pkg, ver] of Object.entries(deps)) {
                    if (highRisk.includes(pkg as string)) {
                        findings.push(`Vulnerability check: Found ${pkg}@${ver}. Advise verifying against latest CVEs.`);
                        if (severity === 'LOW') severity = 'MEDIUM';
                    }
                }
            }

            // 2. Python (requirements.txt)
            const reqsPath = path.join(cloneDir, 'requirements.txt');
            if (fs.existsSync(reqsPath)) {
                const text = fs.readFileSync(reqsPath, 'utf8');
                const reqArray = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));
                findings.push(`Detected ${reqArray.length} Python dependencies.`);
                if (text.includes('flask') || text.includes('django')) {
                    findings.push('Web framework detected (Python). Testing for middleware misconfigurations recommended.');
                }
            }

            if (findings.length === 0) {
                findings.push("No obvious dependency files (package.json, requirements.txt) identified in root.");
            }

            return {
                toolName: DependencyScannerTool.name,
                findings,
                severity
            };

        } catch (e: any) {
            return {
                toolName: DependencyScannerTool.name,
                findings: [`Dependency scan failed: ${e.message}`],
                error: e.message
            };
        }
    }
};
