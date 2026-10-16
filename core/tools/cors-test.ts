import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const CorsTestTool: Tool = {
    name: 'cors_test',
    description: 'Verifies CORS policy misconfigurations by sending mock Origin headers.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            // Send a request with a fake origin to see how the server responds
            const response = await fetch(target, {
                signal,
                method: 'OPTIONS',
                headers: { 'Origin': 'https://attacker.com' }
            });

            const acao = response.headers.get('access-control-allow-origin');
            const findings = [];

            if (acao === '*' || acao === 'https://attacker.com') {
                findings.push(`CORS allows arbitrary origins on ${target} (INFO: CORS is not access control; real protection comes from auth)`);
            }

            return {
                findings,
                requestsMade: 1,
                data: {
                    severity: 'INFO',
                    status: response.status,
                    allowOrigin: acao,
                    allowMethods: response.headers.get('access-control-allow-methods')
                }
            };
        } catch (e: any) {
            return {
                findings: [`CORS test failed for ${target}: ${e.message}`],
                requestsMade: 1,
                data: { error: e.message }
            };
        }
    }
};
