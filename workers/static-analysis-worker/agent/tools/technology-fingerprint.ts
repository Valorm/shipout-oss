import { AgentTool, AgentContext, ToolResult } from '../types';
import { secureFetchBase } from './http-inspector';

export const TechnologyFingerprintTool: AgentTool = {
    name: 'TechFingerprint',
    description: 'Analyzes HTTP responses and HTML body to fingerprint frameworks (Next.js, React, Rails) and services (Supabase, Firebase, AWS).',

    shouldRun: (ctx: AgentContext) => {
        return ctx.jobType === 'url';
    },

    execute: async (ctx: AgentContext, signal: AbortSignal): Promise<ToolResult> => {
        const findings: string[] = [];
        const baseUrl = ctx.target.startsWith('http') ? ctx.target : `https://${ctx.target}`;

        try {
            const res = await secureFetchBase(baseUrl, signal, ctx);

            const lowerHeaders = Object.fromEntries(
                Array.from(res.headers.entries()).map(([k, v]) => [k.toLowerCase(), v])
            );

            // Header Fingerprinting
            if (lowerHeaders['x-powered-by']) {
                ctx.discoveredTechnologies.add(`Powered-By: ${lowerHeaders['x-powered-by']}`);
            }
            if (lowerHeaders['server']) {
                ctx.discoveredTechnologies.add(`Server: ${lowerHeaders['server']}`);
            }
            if (lowerHeaders['x-nextjs-cache']) {
                ctx.discoveredTechnologies.add(`Framework: Next.js`);
            }

            // HTML Body Fingerprinting
            const html = await res.text();

            if (html.includes('_next/static')) {
                ctx.discoveredTechnologies.add(`Framework: Next.js`);
            }
            if (html.includes('data-reactroot') || html.includes('react-dom')) {
                ctx.discoveredTechnologies.add(`Library: React`);
            }
            if (html.includes('window.supabase') || html.includes('.supabase.co')) {
                ctx.discoveredTechnologies.add(`BaaS: Supabase`);
            }
            if (html.includes('firebase.googleapis.com')) {
                ctx.discoveredTechnologies.add(`BaaS: Firebase`);
            }
            if (html.includes('wp-content/') || html.includes('wp-includes/')) {
                ctx.discoveredTechnologies.add(`CMS: WordPress`);
            }

            const techList = Array.from(ctx.discoveredTechnologies);

            if (techList.length > 0) {
                findings.push(`Successfully identified technologies over surface: ${techList.join(', ')}`);
            } else {
                findings.push(`Unable to passively fingerprint any specific frameworks or backend services from the homepage.`);
            }

            return {
                toolName: TechnologyFingerprintTool.name,
                findings,
                severity: 'LOW',
            };

        } catch (e: any) {
            return {
                toolName: TechnologyFingerprintTool.name,
                findings: [`Fingerprinting failed: ${e.message}`],
                error: e.message
            };
        }
    }
};
