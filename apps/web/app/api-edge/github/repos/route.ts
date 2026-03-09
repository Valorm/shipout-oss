import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

type GitHubRepoResponse = {
  id: number;
  full_name: string;
  private: boolean;
  updated_at: string;
};

export async function OPTIONS() {
  return new Response(null, { status: 200, headers: corsHeaders });
}

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user }, error: userError } = await supabase.auth.getUser();

    if (userError || !user) {
      return NextResponse.json({ error: 'Authentication required' }, { status: 401, headers: corsHeaders });
    }

    const { data: { session }, error: sessionError } = await supabase.auth.getSession();

    if (sessionError || !session) {
      return NextResponse.json({ error: 'Unable to resolve authenticated session' }, { status: 401, headers: corsHeaders });
    }

    const providerToken = (session as any)?.provider_token;
    if (!providerToken) {
      return NextResponse.json(
        { error: 'GitHub provider token unavailable. Reconnect your GitHub account and try again.' },
        { status: 424, headers: corsHeaders }
      );
    }

    const githubResponse = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100', {
      headers: {
        Authorization: `Bearer ${providerToken}`,
        Accept: 'application/vnd.github+json',
      },
      cache: 'no-store',
    });

    if (!githubResponse.ok) {
      return NextResponse.json({ error: 'Failed to load repositories from GitHub' }, { status: 502, headers: corsHeaders });
    }

    const githubRepos = await githubResponse.json();
    const repos: GitHubRepoResponse[] = Array.isArray(githubRepos)
      ? githubRepos.map((repo: any) => ({
        id: repo.id,
        full_name: repo.full_name,
        private: repo.private,
        updated_at: repo.updated_at,
      }))
      : [];

    return NextResponse.json(repos, { headers: corsHeaders });
  } catch (e) {
    console.error('Failed to proxy GitHub repositories:', e);
    return NextResponse.json({ error: 'Unable to fetch repositories' }, { status: 500, headers: corsHeaders });
  }
}
