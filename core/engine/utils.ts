/**
 * Robustly extracts and parses JSON from a string that might contain conversational filler.
 * @param text The raw text from the LLM.
 * @returns The parsed JSON object or null if no valid JSON block is found.
 */
export function extractJSON(text: string): any {
    try {
        // 1. Try direct parse first (cleanest case)
        return JSON.parse(text.trim());
    } catch (e) {
        // 2. Try stripping markdown blocks
        const stripped = text.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();
        try {
            return JSON.parse(stripped);
        } catch (e2) {
            // 3. Try finding the first '{' and last '}'
            const start = text.indexOf('{');
            const end = text.lastIndexOf('}');

            if (start !== -1 && end !== -1 && end > start) {
                const inner = text.substring(start, end + 1);
                try {
                    return JSON.parse(inner);
                } catch (e3) {
                    return null;
                }
            }
            return null;
        }
    }
}

/**
 * Checks if the system has basic network connectivity.
 */
export async function checkConnectivity(): Promise<boolean> {
    try {
        const response = await fetch('https://www.google.com', { method: 'HEAD', signal: AbortSignal.timeout(5000) });
        return response.ok;
    } catch (e) {
        return false;
    }
}
