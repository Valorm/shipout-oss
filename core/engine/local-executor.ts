import { ToolExecutor } from './interfaces';
import { ScanContext, ToolTelemetry } from '../../packages/shared/types/scan-context';
import { ToolInput, ToolOutput } from '../../packages/shared/types/tool';
import { NetworkPolicyEngine } from '../../packages/shared/security-utils/network-policy-engine';
import { availableTools } from '../tools';

/**
 * Collects every URL bearing field of a tool input: the target itself and
 * any URL valued parameter (contextParams.baseUrl is the field the payload
 * probes derive their request URLs from). Only whole string values that are
 * absolute http(s) URLs count as URL bearing, so payload text that merely
 * mentions an address is not treated as an egress target.
 */
export function collectTargetUrls(input: ToolInput): string[] {
    const urls: string[] = [];
    const push = (value: unknown) => {
        if (typeof value === 'string' && value.trim() !== '' && !urls.includes(value)) {
            urls.push(value);
        }
    };

    push(input.target);

    const params = input.contextParams;
    if (params && typeof params === 'object') {
        // baseUrl is URL bearing even when it carries no scheme.
        push(params.baseUrl);
        const visit = (value: unknown) => {
            if (typeof value === 'string') {
                if (/^https?:\/\//i.test(value.trim())) push(value);
            } else if (Array.isArray(value)) {
                value.forEach(visit);
            } else if (value && typeof value === 'object') {
                Object.values(value).forEach(visit);
            }
        };
        Object.values(params).forEach(visit);
    }

    return urls;
}

export class LocalExecutor implements ToolExecutor {
    async executeTool(
        toolName: string,
        input: ToolInput,
        context: ScanContext
    ): Promise<{ result: ToolOutput; telemetry: ToolTelemetry }> {
        const tool = (availableTools as any)[toolName];
        if (!tool) throw new Error(`Tool ${toolName} not found`);

        const startTime = Date.now();
        try {
            // Egress policy gate (docs/trust-boundary.md Zone E: no internal
            // IPs, no metadata APIs). Every URL bearing field is validated
            // before the tool runs; a restricted target fails the tool call.
            for (const url of collectTargetUrls(input)) {
                await NetworkPolicyEngine.validateEgress(url);
            }

            const result = await tool.run(input);
            return {
                result,
                telemetry: {
                    tool: toolName,
                    input: input,
                    duration: Date.now() - startTime,
                    requests: result.requestsMade || 0,
                    success: true,
                    result: result.data || {},
                    timestamp: new Date().toISOString()
                }
            };
        } catch (e: any) {
            return {
                result: { findings: [], error: e.message },
                telemetry: {
                    tool: toolName,
                    input: input,
                    duration: Date.now() - startTime,
                    requests: 0,
                    success: false,
                    result: {},
                    error: e.message,
                    timestamp: new Date().toISOString()
                }
            };
        }
    }
}
