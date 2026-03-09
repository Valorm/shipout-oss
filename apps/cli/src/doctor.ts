import { cliLogger } from '@core/engine/cli-logger';
import * as dotenv from 'dotenv';
import { checkConnectivity } from '@core/engine/utils';

dotenv.config({ path: '.env' });

export async function runDoctor() {
    console.log('\n🩺 Shipout Environment Diagnostic\n');

    // 1. Check Node Version
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
    if (majorVersion >= 18) {
        console.log('✅ Node.js Version:', nodeVersion);
    } else {
        console.log('❌ Node.js Version:', nodeVersion, '(Requires Node 18+)');
    }

    // 2. Check Network Connectivity
    try {
        const isOnline = await checkConnectivity();
        if (isOnline) {
            console.log('✅ Network Connectivity');
        } else {
            console.log('❌ Network Connectivity (Offline or Blocked)');
        }
    } catch (e) {
        console.log('❌ Network Connectivity (Error)');
    }

    // 3. Check API Key
    if (process.env.GEMINI_API_KEY) {
        const masked = process.env.GEMINI_API_KEY.slice(0, 4) + '...' + process.env.GEMINI_API_KEY.slice(-4);
        console.log('✅ GEMINI_API_KEY Found:', masked);
    } else {
        console.log('❌ GEMINI_API_KEY Missing');
    }

    // 4. Check Engine Directories
    const fs = require('fs');
    const path = require('path');
    const corePath = path.join(process.cwd(), 'core');
    if (fs.existsSync(corePath)) {
        console.log('✅ Shipout Engine (core/ directory found)');
    } else {
        console.log('❌ Shipout Engine (core/ directory MISSING)');
    }

    console.log('\n--- Diagnostic Complete ---\n');
}
