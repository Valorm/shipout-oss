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

    private agentStatuses: Map<string, string> = new Map();

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

        // Extract agent name if present in brackets [AgentName]
        const agentMatch = text.match(/^\[(.*?)\]/);
        const agentName = agentMatch ? agentMatch[1] : 'Orchestrator';
        const cleanText = text.replace(/^\[.*?\]\s*/, '');

        this.agentStatuses.set(agentName, cleanText);

        if (this.debug) {
            console.log(chalk.gray(`[${agentName}] ${cleanText} (${progress || 0}%)`));
        } else {
            // In non-debug mode, we'll show a compact real-time update
            // We'll use a single line for the "latest" high-priority agent action
            if (agentName.includes('Worker') || agentName === 'PayloadAgent') {
                process.stdout.write(chalk.dim(`\r      • Parallel Activity: ${chalk.yellow(agentName)} is ${cleanText.toLowerCase().slice(0, 40)}...          `));
            } else {
                console.log(`      ${chalk.dim('•')} ${chalk.bold(agentName)}: ${chalk.dim(cleanText)}`);
            }
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
        console.log(`Duration: ${chalk.bold(duration + 's')}`);
        console.log(`Requests: ${context.requestsMade}`);
        console.log(`Endpoints: ${context.discoveredEndpoints.length}`);
        console.log(`Vulnerabilities: ${vulnerabilities.length > 0 ? chalk.red.bold(vulnerabilities.length) : '0'}`);
        console.log(`Informational Findings: ${infoFindings.length}`);

        if (context.discoveredEndpoints.length > 0) {
            console.log(`\n${chalk.bold('🔎 Discovered Endpoints')}`);
            console.log(chalk.dim('----------------------------------------'));
            const showCount = Math.min(context.discoveredEndpoints.length, 10);
            context.discoveredEndpoints.slice(0, showCount).forEach(ep => {
                console.log(chalk.dim(ep));
            });
            if (context.discoveredEndpoints.length > showCount) {
                console.log(chalk.dim(`... and ${context.discoveredEndpoints.length - showCount} more`));
            }
        }

        if (context.vulnerabilities.length > 0) {
            console.log(`\n${chalk.bold('🚨 Vulnerabilities')}`);
            console.log(chalk.dim('----------------------------------------'));

            const severities: ('CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO')[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

            severities.forEach(sev => {
                const filtered = context.vulnerabilities.filter(v => v.severity === sev);
                if (filtered.length > 0) {
                    let color: (str: string) => string = (s) => s;
                    if (sev === 'CRITICAL') color = chalk.bgRed.white.bold;
                    else if (sev === 'HIGH') color = chalk.red.bold;
                    else if (sev === 'MEDIUM') color = chalk.yellow.bold;
                    else if (sev === 'LOW') color = chalk.yellow;
                    else if (sev === 'INFO') color = chalk.blue;

                    filtered.forEach(v => {
                        console.log(`\n[${color(sev)}] ${chalk.bold(v.description)}`);

                        if (v.endpoint) {
                            console.log(`\n${chalk.dim('Endpoint:')}`);
                            console.log(chalk.yellow(v.endpoint));
                        }

                        if (v.parameter) {
                            console.log(`\n${chalk.dim('Parameter:')}`);
                            console.log(v.parameter);
                        }

                        if (v.payload) {
                            console.log(`\n${chalk.dim('Payload:')}`);
                            console.log(chalk.cyan(v.payload));
                        }

                        if (v.evidence) {
                            console.log(`\n${chalk.dim('Evidence:')}`);
                            if (typeof v.evidence === 'string') {
                                console.log(v.evidence);
                            } else {
                                console.log(JSON.stringify(v.evidence, null, 2));
                            }
                        }

                        if (v.agent) {
                            console.log(`\n${chalk.dim('Agent:')}`);
                            console.log(chalk.green(v.agent));
                        }
                        console.log(chalk.dim('---'));
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
