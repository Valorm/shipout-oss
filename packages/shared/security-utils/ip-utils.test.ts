import { describe, expect, it } from 'vitest';
import { isInternalHostname, isRestrictedIp } from './ip-utils';

describe('isRestrictedIp', () => {
    it('blocks RFC1918 IPv4 ranges', () => {
        expect(isRestrictedIp('10.1.2.3')).toBe(true);
        expect(isRestrictedIp('172.16.0.1')).toBe(true);
        expect(isRestrictedIp('192.168.100.200')).toBe(true);
    });

    it('blocks loopback and metadata targets', () => {
        expect(isRestrictedIp('127.0.0.1')).toBe(true);
        expect(isRestrictedIp('169.254.169.254')).toBe(true);
    });

    it('blocks IPv6 private and link-local ranges', () => {
        expect(isRestrictedIp('::1')).toBe(true);
        expect(isRestrictedIp('fc00::1')).toBe(true);
        expect(isRestrictedIp('fe80::1')).toBe(true);
    });

    it('allows public IPv4 and IPv6 addresses', () => {
        expect(isRestrictedIp('1.1.1.1')).toBe(false);
        expect(isRestrictedIp('8.8.8.8')).toBe(false);
        expect(isRestrictedIp('2606:4700:4700::1111')).toBe(false);
    });

    it('returns false for malformed inputs', () => {
        expect(isRestrictedIp('not-an-ip')).toBe(false);
        expect(isRestrictedIp('999.999.999.999')).toBe(false);
    });
});

describe('isInternalHostname', () => {
    it('blocks internal hostnames', () => {
        expect(isInternalHostname('localhost')).toBe(true);
        expect(isInternalHostname('db.internal')).toBe(true);
        expect(isInternalHostname('printer.local')).toBe(true);
    });

    it('allows normal public hostnames', () => {
        expect(isInternalHostname('example.com')).toBe(false);
    });
});
