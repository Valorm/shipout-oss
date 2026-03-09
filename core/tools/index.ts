import { Tool } from '@shared/types/tool';

import { HttpProbeTool } from './http-probe';
import { EndpointDiscoveryTool } from './endpoint-discovery';
import { HeaderAnalysisTool } from './header-analysis';
import { CorsTestTool } from './cors-test';
import { CookieAnalysisTool } from './cookie-analysis';
import { RateLimitTestTool } from './rate-limit-test';
import { JavascriptSecretScanTool } from './javascript-secret-scan';
import { DependencyCveLookupTool } from './dependency-cve-lookup';

import { SQLiProbeTool } from './sqli-probe';
import { XSSProbeTool } from './xss-probe';
import { OpenRedirectProbeTool } from './open-redirect-probe';
import { SSRFProbeTool } from './ssrf-probe';
import { PathTraversalProbeTool } from './path-traversal-probe';
import { PayloadFuzzTool } from './payload-fuzz';
import { JSEndpointMinerTool } from './js-endpoint-miner';
import { WebCrawlerTool } from './web-crawler';
import { RobotsExplorerTool } from './robots-explorer';
import { SitemapAnalyzerTool } from './sitemap-analyzer';
import { SubdomainDiscoveryTool } from './subdomain-discovery';
import { HistoricalDiscoveryTool } from './historical-discovery';
import { ParameterFuzzerTool } from './parameter-fuzzer';

export const availableTools: Record<string, Tool> = {
    'http_probe': HttpProbeTool,
    'endpoint_discovery': EndpointDiscoveryTool,
    'header_analysis': HeaderAnalysisTool,
    'cors_test': CorsTestTool,
    'cookie_analysis': CookieAnalysisTool,
    'rate_limit_test': RateLimitTestTool,
    'javascript_secret_scan': JavascriptSecretScanTool,
    'dependency_cve_lookup': DependencyCveLookupTool,
    'sqli_probe': SQLiProbeTool,
    'xss_probe': XSSProbeTool,
    'open_redirect_probe': OpenRedirectProbeTool,
    'ssrf_probe': SSRFProbeTool,
    'path_traversal_probe': PathTraversalProbeTool,
    'payload_fuzz': PayloadFuzzTool,
    'js_endpoint_miner': JSEndpointMinerTool,
    'web_crawler': WebCrawlerTool,
    'robots_explorer': RobotsExplorerTool,
    'sitemap_analyzer': SitemapAnalyzerTool,
    'subdomain_discovery': SubdomainDiscoveryTool,
    'historical_discovery': HistoricalDiscoveryTool,
    'parameter_fuzzer': ParameterFuzzerTool,
};
