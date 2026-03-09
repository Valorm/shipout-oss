import { createBrowserClient } from '@supabase/ssr';

export function createClient() {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

    // Safety check for build-time/missing env vars
    if (!url || !key) {
        return {
            auth: {
                getSession: async () => ({ data: { session: null }, error: null }),
                getUser: async () => ({ data: { user: null }, error: null }),
                onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => { } } } }),
                signInWithOAuth: async () => ({ data: {}, error: null }),
            },
            channel: () => ({
                on: () => ({ subscribe: () => { } }),
            }),
            from: () => ({
                select: () => ({ eq: () => ({ single: async () => ({ data: null, error: null }) }) }),
            }),
            removeChannel: () => { },
        } as any;
    }

    return createBrowserClient(url, key);
}
