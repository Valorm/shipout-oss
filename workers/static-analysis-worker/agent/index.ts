import { toolRegistry } from './tool-registry';

import { HttpInspectorTool } from './tools/http-inspector';
import { EndpointDiscovererTool } from './tools/endpoint-discovery';
import { RateLimitTesterTool } from './tools/rate-limit-tester';
import { AuthTesterTool } from './tools/auth-tester';
import { SecretDetectionTool } from './tools/secret-detection';
import { TechnologyFingerprintTool } from './tools/technology-fingerprint';
import { DependencyScannerTool } from './tools/dependency-scanner';
import { AbuseSurfaceTesterTool } from './tools/abuse-surface';

// Register all available tools
toolRegistry.registerTool(HttpInspectorTool);
toolRegistry.registerTool(EndpointDiscovererTool);
toolRegistry.registerTool(RateLimitTesterTool);
toolRegistry.registerTool(AuthTesterTool);
toolRegistry.registerTool(SecretDetectionTool);
toolRegistry.registerTool(TechnologyFingerprintTool);
toolRegistry.registerTool(DependencyScannerTool);
toolRegistry.registerTool(AbuseSurfaceTesterTool);

// Export context and orchestrator
export * from './types';
export * from './tool-registry';
export * from './orchestrator';
