import { AgentTool, AgentContext, ToolResult } from '../types';
import { secureFetchBase } from './http-inspector';
import * as path from 'path';

export const EndpointDiscovererTool: AgentTool = {
    name: 'EndpointDiscoverer',
    description: 'Scans robots.txt, sitemap.xml, and base HTML to discover exposed attack surface (API endpoints, admin panels, login routes).',

    shouldRun: (ctx: AgentContext) => {
        return ctx.jobType === 'url';
    },

    execute: async (ctx: AgentContext, signal: AbortSignal): Promise<ToolResult> => {
        const findings: string[] = [];
        const baseUrl = ctx.target.startsWith('http') ? ctx.target : `https://${ctx.target}`;
        let rawDataSnippet = '';

        try {
            // 1. Check robots.txt
            try {
                const robotsUrl = new URL('/robots.txt', baseUrl).toString();
                const res = await secureFetchBase(robotsUrl, signal, ctx);
                if (res.ok) {
                    const text = await res.text();
                    const disallowed = text.split('\n')
                        .map(line => line.trim())
                        .filter(line => line.toLowerCase().startsWith('disallow:'))
                        .map(line => line.split(':')[1]?.trim())
                        .filter(Boolean) as string[];

                    if (disallowed.length > 0) {
                        findings.push(`Found ${disallowed.length} disallowed paths in robots.txt.`);
                        for (const disallowedPath of disallowed.slice(0, 10)) {
                            try {
                                const fullUrl = new URL(disallowedPath, baseUrl).toString();
                                ctx.discoveredEndpoints.add(fullUrl);
                            } catch { } // ignore invalid paths
                        }
                        if (disallowed.some(p => p.includes('admin') || p.includes('login') || p.includes('api'))) {
                            findings.push('robots.txt exposes potentially sensitive administrative or API paths.');
                        }
                    }
                    rawDataSnippet += `--- robots.txt snippet ---\n${text.substring(0, 500)}\n\n`;
                }
            } catch (e: any) {
                findings.push(`Failed to fetch robots.txt: ${e.message}`);
            }

            // 2. Check sitemap.xml
            try {
                const sitemapUrl = new URL('/sitemap.xml', baseUrl).toString();
                const res = await secureFetchBase(sitemapUrl, signal, ctx);
                if (res.ok) {
                    const text = await res.text();
                    const urlsMatch = text.match(/<loc>(.*?)<\/loc>/g);
                    if (urlsMatch) {
                        const urls = urlsMatch.map(u => u.replace(/<\/?loc>/g, ''));
                        findings.push(`Found ${urls.length} paths in sitemap.xml.`);
                        for (const url of urls.slice(0, 10)) {
                            ctx.discoveredEndpoints.add(url);
                        }
                    }
                }
            } catch (e: any) {
                // Not finding a sitemap is normal
            }

            // 3. Scan base HTML for links and scripts
            try {
                const res = await secureFetchBase(baseUrl, signal, ctx);
                if (res.ok) {
                    const html = await res.text();

                    // Regex for internal links
                    const hrefRegex = /href=["']((?:\/|https?:\/\/(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[^"']+)["']/g;
                    let match;
                    let linkCount = 0;
                    while ((match = hrefRegex.exec(html)) !== null && linkCount < 30) {
                        try {
                            const foundUrl = new URL(match[1], baseUrl);
                            if (foundUrl.hostname === new URL(baseUrl).hostname) {
                                ctx.discoveredEndpoints.add(foundUrl.toString());
                                linkCount++;
                            }
                        } catch { }
                    }
                    findings.push(`Discovered ${linkCount} internal links from base HTML.`);

                    // 4. Discovery via Inline/External scripts
                    const scriptRegex = /src=["']((?:\/|https?:\/\/(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[^"']+\.js[^"']*)["']/g;
                    let scriptMatch;
                    let scriptCount = 0;
                    while ((scriptMatch = scriptRegex.exec(html)) !== null && scriptCount < 5) {
                        const scriptUrl = new URL(scriptMatch[1], baseUrl).toString();
                        if (scriptUrl.includes(new URL(baseUrl).hostname)) {
                            try {
                                const sRes = await secureFetchBase(scriptUrl, signal, ctx);
                                if (sRes.ok) {
                                    const js = await sRes.text();
                                    // Look for path-like strings in JS
                                    const pathRegex = /["'](\/[a-zA-Z0-9\/\-_{}.]+)["']/g;
                                    let pMatch;
                                    let pCount = 0;
                                    while ((pMatch = pathRegex.exec(js)) !== null && pCount < 10) {
                                        const foundPath = pMatch[1];
                                        if (foundPath.length > 2 && (foundPath.includes('/') || foundPath.includes('api'))) {
                                            ctx.discoveredEndpoints.add(new URL(foundPath, baseUrl).toString());
                                            pCount++;
                                        }
                                    }
                                    if (pCount > 0) findings.push(`Discovered ${pCount} potential paths from script: ${path.basename(scriptUrl)}`);
                                }
                            } catch { }
                            scriptCount++;
                        }
                    }
                }
            } catch (e: any) {
                findings.push(`Failed to analyze base HTML: ${e.message}`);
            }

            const currentArr = Array.from(ctx.discoveredEndpoints);

            // Highlight sensitive discoveries that should trigger other tools
            let suggestedNextTools: string[] = [];
            if (currentArr.some(e => e.includes('/login') || e.includes('/auth') || e.includes('/signin'))) {
                findings.push('Discovered authentication/login endpoints.');
                suggestedNextTools.push('AuthTester');
            }
            if (currentArr.some(e => e.includes('/api/') || e.includes('/graphql'))) {
                findings.push('Discovered API/GraphQL endpoints.');
                suggestedNextTools.push('RateLimitTester');
            }

            return {
                toolName: EndpointDiscovererTool.name,
                findings: findings.length > 0 ? findings : ['No significant endpoints discovered.'],
                severity: 'LOW',
                rawData: rawDataSnippet,
                suggestedNextTools
            };

        } catch (e: any) {
            return {
                toolName: EndpointDiscovererTool.name,
                findings: [`Endpoint discovery totally failed: ${e.message}`],
                error: e.message
            };
        }
    }
};
