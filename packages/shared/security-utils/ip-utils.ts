import { NetworkRulesPolicy } from '../policies/network-rules.policy';

type IpVersion = 4 | 6;

type CidrRange = {
    cidr: string;
    version: IpVersion;
    network: bigint;
    mask: bigint;
};

const blockedCidrs = [
    ...NetworkRulesPolicy.BLOCKED_EGRESS_CIDRS,
    '169.254.0.0/16',   // Link-local IPv4
    'fe80::/10',        // Link-local IPv6
    '0.0.0.0/8',        // Current network
    '255.255.255.255/32' // Broadcast
].map((cidr) => {
    try {
        return parseCidr(cidr);
    } catch (e) {
        console.error(`Failed to initialize CIDR ${cidr}:`, e);
        return null;
    }
}).filter((cidr): cidr is CidrRange => cidr !== null);

/**
 * Checks if a given IP address is in a restricted range.
 */
export function isRestrictedIp(ip: string): boolean {
    const parsed = parseIp(ip);

    if (!parsed) {
        return false;
    }

    return blockedCidrs.some((cidr) => {
        if (cidr.version !== parsed.version) {
            return false;
        }

        return (parsed.value & cidr.mask) === cidr.network;
    });
}

/**
 * Checks if a hostname looks like a local or internal domain.
 */
export function isInternalHostname(hostname: string): boolean {
    const lower = hostname.toLowerCase();
    return (
        lower === 'localhost' ||
        lower.endsWith('.local') ||
        lower.endsWith('.internal') ||
        lower.endsWith('.lan') ||
        lower.endsWith('.home.arpa')
    );
}

function parseCidr(cidr: string): CidrRange {
    const [ip, prefixText] = cidr.split('/');

    if (!ip || !prefixText) {
        throw new Error('Invalid CIDR format');
    }

    const parsed = parseIp(ip);
    if (!parsed) {
        throw new Error('Invalid CIDR IP');
    }

    const prefix = Number(prefixText);
    const totalBits = parsed.version === 4 ? 32 : 128;

    if (!Number.isInteger(prefix) || prefix < 0 || prefix > totalBits) {
        throw new Error('Invalid CIDR prefix');
    }

    const mask = createMask(totalBits, prefix);
    return {
        cidr,
        version: parsed.version,
        mask,
        network: parsed.value & mask,
    };
}

function parseIp(ip: string): { version: IpVersion; value: bigint } | null {
    const ipv4 = parseIPv4(ip);
    if (ipv4 !== null) {
        return { version: 4, value: ipv4 };
    }

    const ipv6 = parseIPv6(ip);
    if (ipv6 !== null) {
        return { version: 6, value: ipv6 };
    }

    return null;
}

function createMask(totalBits: number, prefix: number): bigint {
    if (prefix === 0) {
        return BigInt(0);
    }

    return ((BigInt(1) << BigInt(prefix)) - BigInt(1)) << BigInt(totalBits - prefix);
}

function parseIPv4(ip: string): bigint | null {
    const octets = ip.split('.');

    if (octets.length !== 4) {
        return null;
    }

    let value = BigInt(0);
    for (const octet of octets) {
        if (!/^\d+$/.test(octet)) {
            return null;
        }

        const num = Number(octet);
        if (num < 0 || num > 255) {
            return null;
        }

        value = (value << BigInt(8)) + BigInt(num);
    }

    return value;
}

function parseIPv6(ip: string): bigint | null {
    const scopedIp = ip.split('%')[0];
    if (!scopedIp) {
        return null;
    }

    let normalizedIp = scopedIp;

    if (normalizedIp.includes('.')) {
        const lastColon = normalizedIp.lastIndexOf(':');
        if (lastColon === -1) {
            return null;
        }

        const ipv4Part = normalizedIp.slice(lastColon + 1);
        const ipv4Value = parseIPv4(ipv4Part);
        if (ipv4Value === null) {
            return null;
        }

        const high = Number((ipv4Value >> BigInt(16)) & BigInt(0xffff)).toString(16);
        const low = Number(ipv4Value & BigInt(0xffff)).toString(16);
        normalizedIp = `${normalizedIp.slice(0, lastColon)}:${high}:${low}`;
    }

    const parts = normalizedIp.split('::');
    if (parts.length > 2) {
        return null;
    }

    const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
    const right = parts[1] ? parts[1].split(':').filter(Boolean) : [];

    if (parts.length === 1 && left.length !== 8) {
        return null;
    }

    const missing = 8 - (left.length + right.length);
    if (missing < 0 || (parts.length === 1 && missing !== 0)) {
        return null;
    }

    const hextets = [
        ...left,
        ...Array.from({ length: missing }, () => '0'),
        ...right,
    ];

    if (hextets.length !== 8) {
        return null;
    }

    let value = BigInt(0);
    for (const hextet of hextets) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(hextet)) {
            return null;
        }

        value = (value << BigInt(16)) + BigInt(parseInt(hextet, 16));
    }

    return value;
}
