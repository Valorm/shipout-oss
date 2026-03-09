import { ScanContext, ScanBudget } from '../../packages/shared/types/scan-context';
import { Agent } from '../../packages/shared/types/agent';
import { AgentPlanner as BasePlanner } from '../../core/engine/planner';
import { ToolExecutor, InvestigationLogger } from '../../core/engine/interfaces';
import { toolRunner } from '../tool-runner';

class SupabaseLogger implements InvestigationLogger {
    private supabase: any;

    constructor() {
        this.initSupabase();
    }

    private async initSupabase() {
        const { getAdminClient } = await import('../database/db');
        this.supabase = getAdminClient();
    }

    async updateStatus(jobId: string, text: string, progress?: number): Promise<void> {
        if (!this.supabase) await this.initSupabase();
        const updateData: any = { status_text: text };
        if (progress !== undefined) updateData.progress = progress;
        await this.supabase.from('jobs').update(updateData).eq('id', jobId);
    }

    logDebug(message: string): void {
        console.log(`[DEBUG] ${message}`);
    }
}

export class AgentPlanner extends BasePlanner {
    constructor(budget: ScanBudget) {
        super(budget, toolRunner, new SupabaseLogger());
    }
}
