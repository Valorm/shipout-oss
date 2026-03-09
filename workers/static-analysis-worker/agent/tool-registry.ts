import { AgentTool, AgentContext } from './types';

export class ToolRegistry {
    private tools: Map<string, AgentTool> = new Map();

    registerTool(tool: AgentTool) {
        if (this.tools.has(tool.name)) {
            throw new Error(`Tool ${tool.name} is already registered.`);
        }
        this.tools.set(tool.name, tool);
    }

    getTool(name: string): AgentTool | undefined {
        return this.tools.get(name);
    }

    getAllTools(): AgentTool[] {
        return Array.from(this.tools.values());
    }

    /**
     * Returns a list of all tools that currently evaluate shouldRun() to true.
     */
    getApplicableTools(ctx: AgentContext): AgentTool[] {
        return this.getAllTools().filter(tool => tool.shouldRun(ctx));
    }

    /**
     * Returns a summarized string of available tools for the AI prompt.
     */
    getToolDescriptionsForPrompt(ctx: AgentContext): string {
        // Only show tools that haven't already run (unless they explicitly want to run again)
        // For simplicity, we filter out tools that have a result in the context
        const availableTools = this.getAllTools().filter(t => !ctx.toolResults[t.name]);

        return availableTools.map(t => `- **${t.name}**: ${t.description}`).join('\n');
    }
}

// Global singleton instance
export const toolRegistry = new ToolRegistry();
