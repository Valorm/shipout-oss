import { isRestrictedIp, isInternalHostname } from '../../shared/security-utils/ip-utils';
import dns from 'dns';

export class NetworkPolicyEngine {
    /**
     * Evaluates a target URL against the established security policies.
     * Throws an error if the egress is prohibited.
     */
    static async validateEgress(targetUrl: string): Promise<void> {
        console.log(`[NetworkPolicyEngine] Evaluating egress request to: ${targetUrl}`);

        try {
            const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
            const hostname = parsed.hostname;

            // 1. Check if target is a direct IP
            const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname) || /^[0-9a-fA-F:]+$/.test(hostname);
            if (isIp) {
                if (isRestrictedIp(hostname)) {
                    throw new Error(`Policy Violation: Direct access to restricted IP ${hostname} is prohibited.`);
                }
                return;
            }

            // 2. Check for internal hostnames (localhost, .local, etc)
            if (isInternalHostname(hostname)) {
                throw new Error(`Policy Violation: Access to internal hostname ${hostname} is prohibited.`);
            }

            // 3. DNS Resolution & IP-level validation (SSRF prevention)
            const addresses = await this.resolveHostname(hostname);
            for (const address of addresses) {
                if (isRestrictedIp(address)) {
                    throw new Error(`Policy Violation: ${hostname} resolves to restricted address ${address}.`);
                }
            }

            console.log(`[NetworkPolicyEngine] Egress permitted to: ${hostname}`);
        } catch (e: any) {
            if (e.message.startsWith('Policy Violation')) {
                console.error(`[NetworkPolicyEngine] BLOCKED: ${e.message}`);
                throw new Error(`Runtime Egress Blocked: ${e.message}`);
            }
            throw new Error(`Invalid egress target: ${e.message}`);
        }
    }

    private static async resolveHostname(hostname: string): Promise<string[]> {
        return await Promise.race([
            dns.promises.resolve(hostname),
            new Promise<string[]>((_, reject) =>
                setTimeout(() => reject(new Error('DNS resolution timed out')), 5000)
            )
        ]);
    }
}
