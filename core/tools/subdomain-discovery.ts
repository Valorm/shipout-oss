import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const SubdomainDiscoveryTool: Tool = {
    name: 'subdomain_discovery',
    description: 'Discovers subdomains using Certificate Transparency logs (crt.sh).',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        let { target } = input;

        // Extract domain from URL if needed
        let domain = target;
        try {
            const url = new URL(target);
            domain = url.hostname;
        } catch {
            // Keep as is
        }

        // crt.sh API (JSON output)
        const apiUrl = `https://crt.sh/?q=${domain}&output=json`;

        try {
            const response = await fetch(apiUrl, { signal });
            if (!response.ok) {
                return {
                    findings: [],
                    requestsMade: 1,
                    error: `crt.sh returned ${response.status}`,
                    data: { error: `crt.sh returned ${response.status}`, status: response.status }
                };
            }

            const data = await response.json();
            const subdomains = new Set<string>();

            if (Array.isArray(data)) {
                data.forEach((entry: any) => {
                    const name = entry.name_value;
                    if (name) {
                        // crt.sh can return multiple names separated by \n
                        name.split('\n').forEach((n: string) => {
                            const cleanName = n.trim().toLowerCase();
                            if (cleanName.includes(domain) && !cleanName.startsWith('*.')) {
                                subdomains.add(cleanName);
                            }
                        });
                    }
                });
            }

            const result = Array.from(subdomains);

            return {
                findings: [`Identified ${result.length} unique subdomains for ${domain} via CT logs.`],
                requestsMade: 1,
                data: {
                    domain,
                    subdomains: result,
                    count: result.length
                }
            };
        } catch (e: any) {
            return {
                findings: [],
                requestsMade: 1,
                error: e.message,
                data: { error: e.message }
            };
        }
    }
};
