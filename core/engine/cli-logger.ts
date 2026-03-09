import chalk from 'chalk';
import { ScanContext, Finding, ScanPhase } from '../../packages/shared/types/scan-context';
import { InvestigationLogger } from './interfaces';

export class CLILogger implements InvestigationLogger {
    private debug: boolean = false;
    private silent: boolean = false;
    private currentPhase: ScanPhase | null = null;
    private phaseOrder: ScanPhase[] = ['reconnaissance', 'surface_mapping', 'vulnerability_analysis', 'verification'];
    private phaseMap: Record<ScanPhase, string> = {
        'reconnaissance': 'Reconnaissance',
        'surface_mapping': 'Surface Expansion',
        'vulnerability_analysis': 'Fuzzing & Injection',
        'verification': 'Vulnerability Verification'
    };

    constructor(debug: boolean = false) {
        this.debug = debug;
    }

    public setDebug(debug: boolean) {
        this.debug = debug;
    }

    public setSilent(silent: boolean) {
        this.silent = silent;
    }

    async updateStatus(jobId: string, text: string, progress?: number): Promise<void> {
        if (this.silent) return;
        if (this.debug) {
            console.log(chalk.gray(`[Status] ${text} (${progress || 0}%)`));
        }
    }

    public start(target: string, budget: number) {
        if (this.silent) return;
        console.log(`\n${chalk.bold('🚀 Shipout Autonomous Scan')}`);
        console.log(`📡 Target: ${chalk.yellow(target)}`);
        console.log(`⚙️  Mode:   Autonomous\n`);

        if (this.debug) {
            console.log(chalk.dim(`[DEBUG] Budget: ${budget} steps`));
        }
    }

    public logTargetProfile(context: ScanContext) {
        if (this.silent) return;
        const waf = context.headers['server']?.toLowerCase().includes('cloudflare') ? chalk.yellow('Cloudflare') : 'None detected';
        const framework = context.technologies.find(t => ['Next.js', 'React', 'Vercel', 'Vue', 'Angular'].includes(t)) || 'Static/Generic';
        const server = context.headers['server'] || 'Unknown';

        console.log(chalk.bold('Target Profile'));
        console.log(chalk.dim('--------------'));
        console.log(`WAF:       ${waf}`);
        console.log(`Framework: ${chalk.green(framework)}`);
        console.log(`Server:    ${server}\n`);
    }

    private progress(current: number, total: number, label: string) {
        const percent = Math.floor((current / total) * 100);
        const filled = Math.floor(percent / 10);
        const bar = "█".repeat(filled) + "░".repeat(10 - filled);
        return `[${chalk.green(bar)}] ${chalk.bold(percent + '%')} ${label}`;
    }

    public logPhase(phase: ScanPhase) {
        if (this.silent) return;
        if (this.currentPhase && this.currentPhase !== phase) {
            console.log(`   ${chalk.green('✓')} ${this.phaseMap[this.currentPhase]} complete`);
        }

        if (this.currentPhase !== phase) {
            this.currentPhase = phase;
            const index = this.phaseOrder.indexOf(phase) + 1;
            const total = this.phaseOrder.length;
            console.log(`\n${this.progress(index, total, this.phaseMap[phase] || phase)}`);
        }
    }

    public logToolExecute(tool: string, reason: string) {
        if (this.silent) return;
        if (this.debug) {
            console.log(chalk.dim(`[DEBUG] Executing ${tool}: ${reason}`));
        }
    }

    public logToolResult(tool: string, findingsCount: number, success: boolean, error?: string) {
        if (this.silent) return;
        const icon = success ? chalk.green('✓') : chalk.red('✗');
        const toolName = tool.replace(/_/g, ' ');

        if (this.debug) {
            if (success) {
                if (findingsCount > 0) {
                    console.log(`   ${icon} ${toolName}: ${chalk.bold(findingsCount)} findings`);
                } else {
                    console.log(`   ${icon} ${toolName} complete`);
                }
            } else {
                console.log(`   ${icon} ${toolName} ${chalk.red('failed')}: ${error || 'Unknown error'}`);
            }
        } else if (success) {
            console.log(`      ${icon} ${chalk.dim(toolName)}`);
        }
    }

    public logAgentChange(from: string, to: string, reason: string) {
        if (this.silent) return;
        if (this.debug) {
            console.log(chalk.dim(`[DEBUG] Agent: ${from} -> ${to} (${reason})`));
        } else {
            console.log(`\n   ${chalk.yellow('→')} ${chalk.bold(to)} focusing on: ${chalk.dim(reason.split('.')[0])}`);
        }
    }

    public logInvestigationStep(agent: string, action: string) {
        if (this.silent) return;
        if (this.debug) return;
        console.log(`      ${chalk.dim('•')} ${action}`);
    }

    public logStrategy(strategy: string) {
        if (this.silent) return;
        if (this.debug) {
            console.log(chalk.dim(`[DEBUG] Strategy: ${strategy}`));
        }
    }

    public logObjective(description: string, status: string) {
        if (this.silent) return;
        if (this.debug) {
            console.log(chalk.dim(`[DEBUG] Objective: ${description} -> ${status}`));
        }
    }

    public logDebug(message: string) {
        if (this.silent) return;
        if (this.debug) {
            console.log(chalk.dim(`[DEBUG] ${message}`));
        }
    }

    public logSummary(context: ScanContext) {
        if (this.silent) return;

        if (this.currentPhase) {
            console.log(`   ${chalk.green('✓')} ${this.phaseMap[this.currentPhase]} complete`);
        }

        console.log(`\n${this.progress(4, 4, 'Scan Complete')}`);

        const duration = ((Date.now() - context.startTime) / 1000).toFixed(1);
        const vulnerabilities = context.vulnerabilities.filter(v => v.severity !== 'INFO');
        const infoFindings = context.vulnerabilities.filter(v => v.severity === 'INFO');

        console.log(`\n${chalk.bold('📊 Scan Summary')}`);
        console.log(chalk.dim('----------------------------------------'));
        console.log(`- Scan duration: ${chalk.bold(duration + 's')}`);
        console.log(`- Requests made: ${context.requestsMade}`);
        console.log(`- Endpoints discovered: ${context.discoveredEndpoints.length}`);
        console.log(`- Vulnerabilities: ${vulnerabilities.length > 0 ? chalk.red.bold(vulnerabilities.length) : '0'}`);
        console.log(`- Informational Findings: ${infoFindings.length}`);

        if (context.agentsUsed && context.agentsUsed.length > 0) {
            console.log(`\n${chalk.bold('🤖 Agents Used')}`);
            console.log(chalk.dim('-----------'));
            context.agentsUsed.forEach(agent => {
                console.log(chalk.yellow(agent));
            });
        }

        if (context.vulnerabilities.length > 0) {
            console.log(`\n${chalk.bold('🚨 Findings')}`);
            console.log(chalk.dim('----------------'));

            const severities: ('CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO')[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

            severities.forEach(sev => {
                const filtered = context.vulnerabilities.filter(v => v.severity === sev);
                if (filtered.length > 0) {
                    let color: (str: string) => string = (s) => s;
                    let icon = '⚪';
                    if (sev === 'CRITICAL') { color = chalk.bgRed.white.bold; icon = '🔴'; }
                    else if (sev === 'HIGH') { color = chalk.red.bold; icon = '🔴'; }
                    else if (sev === 'MEDIUM') { color = chalk.yellow.bold; icon = '🟠'; }
                    else if (sev === 'LOW') { color = chalk.yellow.bold; icon = '🟡'; }
                    else if (sev === 'INFO') { color = chalk.green.bold; icon = '🟢'; }

                    console.log(`\n${color(sev)}`);
                    filtered.forEach(v => {
                        console.log(` ${icon} ${v.description}`);
                    });
                }
            });
        } else {
            console.log(`\n${chalk.green.bold('✨ No vulnerabilities confirmed.')}`);
        }

        console.log(`\n${chalk.dim('----------------------------------------')}`);
        const criticalCount = context.vulnerabilities.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length;
        if (criticalCount > 0) {
            console.log(`${chalk.red.bold(`Scan result: ${criticalCount} high-risk vulnerabilities found.`)}\n`);
        } else {
            console.log(`${chalk.green.bold('Scan result: No critical vulnerabilities detected.')}\n`);
        }
    }
}

export const cliLogger = new CLILogger();
