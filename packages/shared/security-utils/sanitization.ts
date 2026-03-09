/**
 * Sanitizes a string to prevent XSS by escaping HTML special characters.
 */
export function sanitizeHtml(str: string): string {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * Recursively sanitizes all string properties in an object.
 */
export function sanitizeObject<T>(obj: T): T {
    if (typeof obj !== 'object' || obj === null) {
        return typeof obj === 'string' ? (sanitizeHtml(obj) as any) : obj;
    }

    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObject(item)) as any;
    }

    const result: any = {};
    for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
            result[key] = sanitizeObject((obj as any)[key]);
        }
    }
    return result;
}
