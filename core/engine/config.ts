import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface ShipoutConfig {
    gemini_api_key?: string;
}

export class ConfigManager {
    private static readonly CONFIG_DIR = path.join(os.homedir(), '.shipout');
    private static readonly CONFIG_FILE = path.join(ConfigManager.CONFIG_DIR, 'config.json');

    public static getConfigPath(): string {
        return this.CONFIG_FILE;
    }

    public static async saveConfig(config: ShipoutConfig): Promise<void> {
        if (!fs.existsSync(this.CONFIG_DIR)) {
            fs.mkdirSync(this.CONFIG_DIR, { recursive: true });
        }
        fs.writeFileSync(this.CONFIG_FILE, JSON.stringify(config, null, 2));
    }

    public static loadConfig(): ShipoutConfig {
        try {
            if (fs.existsSync(this.CONFIG_FILE)) {
                const data = fs.readFileSync(this.CONFIG_FILE, 'utf8');
                return JSON.parse(data);
            }
        } catch (e) {
            // Silence load errors, return empty
        }
        return {};
    }

    /**
     * Resolves the API key based on priority:
     * 1. CLI Flag (--api-key)
     * 2. ~/.shipout/config.json
     * 3. .env file
     * 4. Environment variable
     */
    public static resolveApiKey(cliFlag?: string): string | undefined {
        // 1. CLI Flag
        if (cliFlag) return cliFlag;

        // 2. Config File
        const config = this.loadConfig();
        if (config.gemini_api_key) return config.gemini_api_key;

        // 3 & 4. .env / Env Var (already handled by process.env if loaded)
        return process.env.GEMINI_API_KEY;
    }
}
