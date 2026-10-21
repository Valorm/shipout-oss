import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { LocalExecutor, collectTargetUrls } from '../core/engine/local-executor';
import { HttpProbeTool } from '../core/tools/http-probe';
import { ScanContext } from '../packages/shared/types/scan-context';

// Public IP literal (example.com's address). The egress policy classifies
// IP literals locally, so these tests need no DNS and no network.
const PUBLIC_IP_URL = 'http://93.184.216.34';
const METADATA_URL = 'http://169.254.169.254/latest/meta-data';

function fakeResponse(status: number, headers: Record<string, string> = {}): Response {
    return new Response(null, { status, headers });
}

describe('collectTargetUrls', () => {
    it('collects the target and URL bearing context params', () => {
        const urls = collectTargetUrls({
            target: 'https://example.com',
            contextParams: {
                baseUrl: 'https://example.com/app',
                endpoints: ['https://example.com/api/users'],
                note: 'plain text'
            }
        });
        expect(urls).toContain('https://example.com');
        expect(urls).toContain('https://example.com/app');
        expect(urls).toContain('https://example.com/api/users');
        expect(urls).not.toContain('plain text');
    });

    it('does not treat payload text mentioning an address as a target', () => {
        const urls = collectTargetUrls({
            target: 'https://example.com',
            contextParams: { payload: `fetch("${METADATA_URL}")` }
        });
        expect(urls).toEqual(['https://example.com']);
    });
});

describe('LocalExecutor egress gate', () => {
    const fetchMock = vi.fn();
    const context = { target: PUBLIC_IP_URL } as unknown as ScanContext;
    const executor = new LocalExecutor();

    beforeEach(() => {
        fetchMock.mockReset();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('refuses a restricted target before the tool runs', async () => {
        const { result, telemetry } = await executor.executeTool(
            'http_probe',
            { target: METADATA_URL },
            context
        );

        expect(fetchMock).not.toHaveBeenCalled();
        expect(telemetry.success).toBe(false);
        expect(result.error).toContain('Egress Blocked');
        expect(result.error).toContain('169.254.169.254');
    });

    it('refuses an internal hostname carried in contextParams.baseUrl', async () => {
        const { result, telemetry } = await executor.executeTool(
            'http_probe',
            { target: PUBLIC_IP_URL, contextParams: { baseUrl: 'http://localhost:8080' } },
            context
        );

        expect(fetchMock).not.toHaveBeenCalled();
        expect(telemetry.success).toBe(false);
        expect(result.error).toContain('Egress Blocked');
        expect(result.error).toContain('localhost');
    });

    it('lets an allowed public target through to the tool', async () => {
        fetchMock.mockResolvedValue(fakeResponse(200, { server: 'test-server' }));

        const { result, telemetry } = await executor.executeTool(
            'http_probe',
            { target: PUBLIC_IP_URL },
            context
        );

        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(telemetry.success).toBe(true);
        expect(result.error).toBeUndefined();
        expect(result.data.status).toBe(200);
    });
});

describe('HttpProbeTool redirect handling', () => {
    const fetchMock = vi.fn();

    beforeEach(() => {
        fetchMock.mockReset();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('refuses a redirect to a restricted address without requesting it', async () => {
        fetchMock.mockResolvedValue(fakeResponse(302, { location: METADATA_URL }));

        const result = await HttpProbeTool.run({ target: `${PUBLIC_IP_URL}/start` });

        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(fetchMock.mock.calls[0][0]).toBe(`${PUBLIC_IP_URL}/start`);
        expect(result.error).toContain('Egress Blocked');
        expect(result.requestsMade).toBe(1);
    });

    it('follows a redirect to an allowed address and reports it', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse(302, { location: `${PUBLIC_IP_URL}/final` }))
            .mockResolvedValueOnce(fakeResponse(200, { server: 'test-server' }));

        const result = await HttpProbeTool.run({ target: `${PUBLIC_IP_URL}/start` });

        expect(fetchMock).toHaveBeenCalledTimes(2);
        expect(result.error).toBeUndefined();
        expect(result.requestsMade).toBe(2);
        expect(result.data.status).toBe(200);
        expect(result.data.redirected).toBe(true);
        expect(result.data.server).toBe('test-server');
    });

    it('stops at the redirect cap', async () => {
        fetchMock.mockResolvedValue(fakeResponse(302, { location: `${PUBLIC_IP_URL}/loop` }));

        const result = await HttpProbeTool.run({ target: `${PUBLIC_IP_URL}/start` });

        expect(result.error).toContain('Too many redirects');
        expect(result.requestsMade).toBe(6);
    });
});
