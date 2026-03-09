'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Image from 'next/image';
import { motion, AnimatePresence } from 'motion/react';
import { createClient } from '@/utils/supabase/client';
import {
  Shield, Activity, Lock, AlertTriangle, CheckCircle,
  Terminal, Server, Globe, Github, ArrowRight, Loader2,
  Search, Menu, X, Database, Cpu, Network, History, ChevronLeft, ChevronRight, ChevronDown,
  FileDown, Printer, Clock, LogOut, Info, ShieldCheck
} from 'lucide-react';

import { Logo } from '@shared/Logo';


type InvestigationStep = {
  stepIndex: number;
  timestamp: string;
  reasoning: string;
  toolsExecuted: string[];
  keyFindings: string[];
};

type ScanResult = {
  score: number | null;
  confidence?: number;
  coverage?: {
    pages?: number;
    endpoints?: number;
    forms?: number;
    headers?: number;
    scripts?: number;
  };
  checksCompleted?: number;
  totalChecks?: number;
  criticalIssues: string[];
  warnings: string[];
  fixes: { file?: string; description: string; codeSnippet?: string }[];
  riskCategories: string[];
  checklist: { id: string; name: string; status: 'PASS' | 'WARN' | 'FAIL' | 'UNKNOWN'; reason?: string }[];
  investigationSteps?: InvestigationStep[];
  statusText?: string;
};


type HistoryItem = {
  id: string;
  target: string;
  type: 'url' | 'repo';
  date: string;
  score: number | null;
  confidence?: number;
  checksCompleted?: number;
  totalChecks?: number;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'BLOCKED';
};

type HistoryDetails = ScanResult & {
  id: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'BLOCKED';
  completedAt?: string;
};

type GitHubRepository = {
  id: number;
  full_name: string;
  private: boolean;
  updated_at: string;
};

const repoTargetPattern = /([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git|\/)?$/;

const normalizeRepoTarget = (value: string): string => {
  const trimmedValue = value.trim();
  const match = trimmedValue.match(repoTargetPattern);
  if (!match) return trimmedValue;
  return `${match[1]}/${match[2]}`;
};


const InvestigationTimeline = ({ steps }: { steps: InvestigationStep[] }) => {
  if (!steps || steps.length === 0) return null;

  return (
    <div className="space-y-4">
      <h3 className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider flex items-center gap-1.5">
        <Activity className="w-3 h-3 text-poly-accent" />
        Investigation Timeline
      </h3>
      <div className="relative pl-4 space-y-6 before:absolute before:left-[7px] before:top-2 before:bottom-2 before:w-[1px] before:bg-poly-border">
        {steps.map((step, idx) => (
          <div key={idx} className="relative">
            <div className="absolute -left-[13px] top-1.5 w-[9px] h-[9px] rounded-full bg-poly-accent border-2 border-poly-bg z-10"></div>
            <div className="poly-card p-3 space-y-2 hover:border-poly-border-light transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-bold text-poly-accent font-mono uppercase">Step {step.stepIndex}</span>
                  <span className="text-poly-text-dim text-[16px] leading-none">·</span>
                  <div className="flex flex-wrap gap-1">
                    {step.toolsExecuted.map(tool => (
                      <span key={tool} className="text-[9px] font-semibold bg-poly-panel px-1.5 py-0.5 rounded border border-poly-border text-poly-text-muted">
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>
                <span className="text-[9px] font-mono text-poly-text-dim">
                  {new Date(step.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
              </div>
              <p className="text-[12px] font-medium text-white leading-tight">{step.reasoning}</p>
              {step.keyFindings.length > 0 && (
                <div className="space-y-1 pt-1">
                  {step.keyFindings.map((finding, fIdx) => (
                    <div key={fIdx} className="flex items-start gap-2 text-[11px] text-poly-text-muted">
                      <div className="mt-1 w-1 h-1 rounded-full bg-poly-text-dim shrink-0"></div>
                      <span>{finding}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default function ShipoutAudit() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const [userProfile, setUserProfile] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'new_scan' | 'history'>('new_scan');
  const [scanType, setScanType] = useState<'url' | 'repo'>('url');
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const [scheduledInterval, setScheduledInterval] = useState('none');

  const [history, setHistory] = useState<HistoryItem[]>([]);

  const [historyDetails, setHistoryDetails] = useState<Record<string, HistoryDetails>>({});
  const [currentPage, setCurrentPage] = useState(1);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [stats, setStats] = useState({ requests_blocked: 0, unauthorized_access: 0 });
  const [showScope, setShowScope] = useState(false);
  const [repoInputMode, setRepoInputMode] = useState<'select' | 'paste'>('select');
  const [githubRepos, setGithubRepos] = useState<GitHubRepository[]>([]);
  const [isLoadingRepos, setIsLoadingRepos] = useState(false);
  const [repoFetchError, setRepoFetchError] = useState('');
  const itemsPerPage = 10;

  const supabase = useMemo(() => createClient(), []);

  // Terminal scroll logic
  const terminalViewportRef = React.useRef<HTMLDivElement>(null);
  const scrollToBottom = useCallback(() => {
    const terminal = terminalViewportRef.current;
    if (!terminal) return;

    terminal.scrollTo({
      top: terminal.scrollHeight,
      behavior: 'smooth'
    });
  }, []);

  useEffect(() => {
    if (scanLogs.length > 0) {
      scrollToBottom();
    }
  }, [scanLogs, scrollToBottom]);

  const API_URL = (process.env.NEXT_PUBLIC_PLATFORM_URL || '').replace(/\/$/, '');

  const totalPages = Math.max(1, Math.ceil(history.length / itemsPerPage));
  const currentHistory = history.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const fetchHistory = useCallback(async () => {
    if (!isAuthenticated) return;

    try {
      const res = await fetch(`${API_URL}/api-edge/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (err: any) {
      console.error('[Shipout] Failed to load history:', err);
      // Log structured error if possible
      if (err.message) {
        console.error(`[Shipout] History Error Details: ${err.message}`);
      }
    }
  }, [isAuthenticated, API_URL]);

  const fetchStats = useCallback(async () => {
    if (!isAuthenticated) return;

    try {
      const res = await fetch(`${API_URL}/api-edge/metrics`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e: any) {
      console.error('[Shipout] Failed to fetch stats:', e);
      if (e.message) {
        console.error(`[Shipout] Metrics Error Details: ${e.message}`);
      }
    }
  }, [isAuthenticated, API_URL]);

  // FIX: supabase is now stable (from useMemo), so this effect runs once on mount
  // and doesn't create duplicate subscriptions.
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const { data: { session }, error } = await supabase.auth.getSession();
        if (session && !error) {
          setIsAuthenticated(true);
          setUserProfile(session.user.user_metadata);
        } else {
          setIsAuthenticated(false);
        }
      } catch (err) {
        setIsAuthenticated(false);
      }
    };

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event: string, session: any) => {
      if (session) {
        setIsAuthenticated(true);
        setUserProfile(session.user.user_metadata);
      } else {
        setIsAuthenticated(false);
        setHistory([]);
      }
    });

    checkAuth();
    return () => subscription.unsubscribe();
  }, [supabase]);

  // FIX: Fetch history and stats in a separate effect, triggered when auth state resolves
  useEffect(() => {
    if (isAuthenticated) {
      fetchHistory();
      fetchStats();
    }
  }, [isAuthenticated, fetchHistory, fetchStats]);

  useEffect(() => {
    const fetchGithubRepos = async () => {
      if (!isAuthenticated || scanType !== 'repo' || repoInputMode !== 'select') return;
      if (githubRepos.length > 0) return;

      setIsLoadingRepos(true);
      setRepoFetchError('');

      try {
        const reposRes = await fetch(`${API_URL}/api-edge/github/repos`, { cache: 'no-store' });

        if (!reposRes.ok) {
          const errorResponse = await reposRes.json().catch(() => ({}));
          throw new Error(errorResponse.error || 'Unable to load repositories from GitHub');
        }

        const repos = await reposRes.json();
        const normalizedRepos: GitHubRepository[] = Array.isArray(repos)
          ? repos.map((repo: any) => ({
            id: repo.id,
            full_name: repo.full_name,
            private: repo.private,
            updated_at: repo.updated_at,
          }))
          : [];

        setGithubRepos(normalizedRepos);
      } catch (e) {
        console.error('Failed to fetch GitHub repositories:', e);
        setRepoFetchError('Could not load your repositories securely. You can still paste a repository URL.');
        setRepoInputMode('paste');
      } finally {
        setIsLoadingRepos(false);
      }
    };

    fetchGithubRepos();
  }, [isAuthenticated, scanType, repoInputMode, githubRepos.length, API_URL]);

  const handleLogin = async () => {
    const redirectUrl = process.env.NEXT_PUBLIC_SITE_URL
      ? `${process.env.NEXT_PUBLIC_SITE_URL}/auth/callback`
      : `${window.location.origin}/auth/callback`;

    await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: redirectUrl,
        scopes: 'repo',
      },
    });
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    setIsAuthenticated(false);
    setUserProfile(null);
    setHistory([]);
    setHistoryDetails({});
    setActiveTab('new_scan');
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const normalizedTarget = scanType === 'repo' ? normalizeRepoTarget(target) : target.trim();
    if (!normalizedTarget) return;

    if (scanType === 'repo' && !repoTargetPattern.test(normalizedTarget)) {
      setError('Invalid repository format. Choose from your repos or paste owner/repo or a GitHub URL.');
      return;
    }

    setIsScanning(true);
    setResult(null);
    setError('');
    setScanProgress(0);
    setScanStatus('');
    setScanLogs(['Initializing secure environment...']);

    try {
      // 1. Submit to Gateway
      const gatewayRes = await fetch(`${API_URL}/api-edge/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          target: normalizedTarget,
          type: scanType,
          scheduledInterval: scheduledInterval === 'none' ? null : scheduledInterval
        })
      });

      const gatewayData = await gatewayRes.json();
      if (!gatewayRes.ok) {
        console.error('[Shipout] Scan request rejected by gateway:', {
          status: gatewayRes.status,
          statusText: gatewayRes.statusText,
          payload: gatewayData,
        });

        // Explicitly log the technical error to console for inspection
        if (gatewayData.error) {
          console.error(`[Shipout] Technical Error Detail: ${gatewayData.error}`);
        }

        throw new Error(gatewayData.error || 'Gateway rejected request');
      }

      const { jobId } = gatewayData;

      const processJobResult = (row: any) => {
        const finalResult: ScanResult = {
          score: row.score,
          confidence: row.confidence,
          coverage: row.coverage,
          checksCompleted: row.checksCompleted ?? row.checks_completed,
          totalChecks: row.totalChecks ?? row.total_checks,
          criticalIssues: row.critical_issues || [],
          warnings: row.warnings || [],
          fixes: row.fixes || [],
          riskCategories: row.risk_categories || [],
          checklist: row.checklist || [],
          investigationSteps: row.investigation_steps || [],
          statusText: row.status_text || row.statusText,
        };

        if (row.status === 'BLOCKED' || row.status === 'FAILED') {
          setError(finalResult.criticalIssues?.[0] || 'Scan blocked or failed');
        } else {
          setResult(finalResult);
          setScanProgress(100);
          setScanStatus("Scan complete.");
        }

        setIsScanning(false);
        if (isAuthenticated) {
          fetchHistory();
          fetchStats();
        }
      };

      let resolved = false;
      let channel: any = null;

      // Strategy A: Realtime subscription (authenticated users only)
      if (isAuthenticated) {
        channel = supabase.channel(`job-${jobId}`)
          .on(
            'postgres_changes',
            {
              event: 'UPDATE',
              schema: 'public',
              table: 'jobs',
              filter: `id=eq.${jobId}`
            },
            (payload: any) => {
              if (resolved) return;
              const updatedJob = payload.new;

              if (updatedJob.progress !== undefined) setScanProgress(updatedJob.progress);
              if (updatedJob.status_text) {
                setScanStatus(updatedJob.status_text);
                setScanLogs(prev => {
                  if (prev[prev.length - 1] !== updatedJob.status_text) {
                    return [...prev, updatedJob.status_text];
                  }
                  return prev;
                });
              }

              if (['COMPLETED', 'FAILED', 'BLOCKED'].includes(updatedJob.status)) {
                resolved = true;
                clearInterval(pollInterval);
                clearTimeout(timeoutHandle);
                supabase.removeChannel(channel);

                fetch(`${API_URL}/api-edge/scan/${jobId}`)
                  .then(res => res.json())
                  .then(fullJob => processJobResult(fullJob))
                  .catch(err => setError(`Failed to fetch final results: ${err.message}`));
              }
            }
          )
          .subscribe();
      }

      // Strategy B: Polling fallback (works for both auth and anonymous)
      const pollInterval = setInterval(async () => {
        if (resolved) {
          clearInterval(pollInterval);
          return;
        }
        try {
          const pollRes = await fetch(`${API_URL}/api-edge/scan/${jobId}`);
          if (!pollRes.ok) return;
          const row = await pollRes.json();

          if (row) {
            if (row.status === 'RUNNING') {
              if (row.progress !== undefined) setScanProgress(row.progress);
              if (row.status_text) {
                setScanStatus(row.status_text);
                setScanLogs(prev => {
                  if (prev[prev.length - 1] !== row.status_text) {
                    return [...prev, row.status_text];
                  }
                  return prev;
                });
              }
            }

            if (['COMPLETED', 'FAILED', 'BLOCKED'].includes(row.status)) {
              resolved = true;
              clearInterval(pollInterval);
              clearTimeout(timeoutHandle);
              if (channel) supabase.removeChannel(channel);
              processJobResult(row);
            }
          }
        } catch (e) {
          // Poll fetch error — continue retrying
        }
      }, 3000);

      // Hard timeout after 10 minutes to avoid false negatives while jobs are queued.
      const timeoutHandle = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          clearInterval(pollInterval);
          if (channel) supabase.removeChannel(channel);
          setError('Scan timed out waiting for worker execution. The queue may be saturated; please retry.');
          setIsScanning(false);
        }
      }, 600000);
    } catch (err: any) {
      console.error('Scan submission failed:', err);
      setError(err.message);
      setIsScanning(false);
    }
  };

  const fetchHistoryDetails = useCallback(async (jobId: string) => {
    if (historyDetails[jobId]) return;

    try {
      const res = await fetch(`${API_URL}/api-edge/scan/${jobId}`);
      if (!res.ok) return;
      const row = await res.json();

      const details: HistoryDetails = {
        id: row.jobId || jobId,
        status: row.status,
        score: row.score,
        confidence: row.confidence,
        coverage: row.coverage,
        checksCompleted: row.checksCompleted ?? row.checks_completed,
        totalChecks: row.totalChecks ?? row.total_checks,
        criticalIssues: row.critical_issues || [],
        warnings: row.warnings || [],
        fixes: row.fixes || [],
        riskCategories: row.risk_categories || [],
        checklist: row.checklist || [],
        investigationSteps: row.investigation_steps || [],
      };

      setHistoryDetails(prev => ({ ...prev, [jobId]: details }));
    } catch (err) {
      console.error('Failed to fetch history details', err);
    }
  }, [API_URL, historyDetails]);

  const handleRetry = (item: any) => {
    setTarget(item.target);
    setScanType(item.type);
    setResult(null);
    setError('');
    setActiveTab('new_scan');
  };

  const handleDownloadJSON = () => {
    if (!result) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      target,
      timestamp: new Date().toISOString(),
      ...result
    }, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `shipout-audit-${target.replace(/[^a-z0-9]/gi, '-')}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  const handleExportPDF = () => {
    window.print();
  };

  if (isAuthenticated === null) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-poly-bg">
        <Loader2 className="w-6 h-6 text-poly-accent animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated && (activeTab === 'history' || activeTab === 'dashboard')) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-poly-bg text-poly-text font-sans">
        <div className="max-w-md w-full p-6 poly-card space-y-6 text-center">
          <div className="w-12 h-12 rounded-md bg-poly-accent/10 border border-poly-accent/20 flex items-center justify-center mx-auto">
            <Lock className="w-6 h-6 text-poly-accent" />
          </div>
          <div>
            <h1 className="text-[17px] font-semibold text-white">Access Restricted</h1>
            <p className="text-poly-text-muted text-[13px] mt-1">Sign in with GitHub to view your audit history and dashboard.</p>
          </div>
          <div className="pt-2 flex flex-col gap-2">
            <button
              onClick={handleLogin}
              className="w-full poly-btn-secondary py-2.5 flex items-center justify-center gap-2 text-[13px]"
            >
              <Github className="w-4 h-4" />
              Sign in with GitHub
            </button>
            <button
              onClick={() => setActiveTab('new_scan')}
              className="text-[11px] text-poly-text-dim hover:text-poly-text-muted font-mono uppercase tracking-wider"
            >
              Back to Public Scan
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-poly-bg text-poly-text font-sans">
      {/* Sidebar */}
      <aside className="w-full md:w-56 poly-sidebar flex flex-col z-10 print:hidden shrink-0">
        <div className="px-4 py-3 flex items-center gap-2.5 border-b border-poly-border">
          <div className="w-14 h-14 flex items-center justify-center text-poly-accent">
            <Logo className="w-full h-full" />
          </div>
          <div>
            <h1 className="font-semibold text-white text-[13px] leading-none">shipout</h1>
            <p className="text-[10px] text-poly-text-muted mt-0.5 tracking-wide">beta</p>
          </div>
        </div>

        <nav className="px-2 py-2 flex-1 space-y-0.5">
          <button
            onClick={() => { setActiveTab('dashboard'); setResult(null); }}
            className={`w-full flex items-center gap-2.5 px-3 py-[7px] rounded-md text-[13px] font-medium transition-colors ${activeTab === 'dashboard' ? 'bg-poly-active text-white' : 'text-poly-text-muted hover:bg-poly-hover hover:text-poly-text'}`}
          >
            <Activity className="w-4 h-4" />
            Overview
          </button>
          <button
            onClick={() => setActiveTab('new_scan')}
            className={`w-full flex items-center gap-2.5 px-3 py-[7px] rounded-md text-[13px] font-medium transition-colors ${activeTab === 'new_scan' ? 'bg-poly-active text-white' : 'text-poly-text-muted hover:bg-poly-hover hover:text-poly-text'}`}
          >
            <Search className="w-4 h-4" />
            New Audit
          </button>
          <button
            onClick={() => { setActiveTab('history'); setResult(null); setCurrentPage(1); }}
            className={`w-full flex items-center gap-2.5 px-3 py-[7px] rounded-md text-[13px] font-medium transition-colors ${activeTab === 'history' ? 'bg-poly-active text-white' : 'text-poly-text-muted hover:bg-poly-hover hover:text-poly-text'}`}
          >
            <History className="w-4 h-4" />
            History
          </button>
        </nav>

        <div className="px-3 py-3 border-t border-poly-border mt-auto">
          <div className="poly-card p-3">
            <div className="flex items-center justify-between">
              <div className="flex flex-col">
                <span className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider">Storage</span>
                <span className="text-[11px] font-mono text-poly-text-dim">4.2GB / 10GB</span>
              </div>
              <div className="p-1 rounded bg-poly-accent/10 border border-poly-border">
                <Database className="w-3.5 h-3.5 text-poly-accent" />
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 relative overflow-hidden flex flex-col">
        {/* Top Header */}
        <header className="h-12 poly-titlebar flex items-center justify-between px-4 z-20 print:hidden">
          <div className="flex items-center gap-2 text-[13px] text-poly-text-muted font-medium">
            <span className="text-poly-text-dim">App</span>
            <span className="text-poly-text-dim">/</span>
            <span className="text-poly-text">{activeTab === 'dashboard' ? 'Overview' : activeTab === 'history' ? 'History' : 'Audit'}</span>
          </div>
          <div className="flex items-center gap-3">
            {isAuthenticated && (
              <button
                onClick={handleLogout}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[12px] font-medium text-poly-text-muted hover:text-white hover:bg-poly-hover transition-colors"
                title="Sign Out"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span className="hidden lg:inline">Sign Out</span>
              </button>
            )}
            <div className="w-7 h-7 rounded-md bg-poly-panel border border-poly-border flex items-center justify-center overflow-hidden">
              {userProfile?.avatar_url ? (
                <Image
                  src={userProfile.avatar_url}
                  alt={userProfile.name || 'User'}
                  width={28}
                  height={28}
                  className="w-full h-full object-cover"
                  unoptimized
                />
              ) : (
                <span className="text-[10px] font-bold text-poly-text-muted">
                  {userProfile?.login?.substring(0, 2).toUpperCase() || 'AD'}
                </span>
              )}
            </div>
          </div>
        </header>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-4 md:p-6">
          <div className="max-w-5xl mx-auto">

            <AnimatePresence mode="wait">
              {activeTab === 'dashboard' && !result && (
                <motion.div
                  key="dashboard"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="space-y-8"
                >
                  <div>
                    <h2 className="text-[15px] font-semibold text-white">System Overview</h2>
                    <p className="text-poly-text-muted text-[13px] mt-0.5">Real-time status of shipout.</p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div className="poly-card p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="p-1.5 rounded-md bg-poly-accent/10">
                          <Globe className="w-4 h-4 text-poly-accent" />
                        </div>
                        <span className="text-[10px] font-semibold text-poly-text-dim uppercase tracking-wider">Edge</span>
                      </div>
                      <h3 className="text-2xl font-bold text-white font-mono">
                        {stats.requests_blocked > 1000 ? `${(stats.requests_blocked / 1000).toFixed(1)}k` : stats.requests_blocked}
                      </h3>
                      <p className="text-[11px] text-poly-text-muted mt-0.5">Blocked Requests (24h)</p>
                    </div>
                    <div className="poly-card p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="p-1.5 rounded-md bg-poly-green/10">
                          <Cpu className="w-4 h-4 text-poly-green" />
                        </div>
                        <span className="text-[10px] font-semibold text-poly-text-dim uppercase tracking-wider">Compute</span>
                      </div>
                      <h3 className="text-2xl font-bold text-white font-mono">{history.length}</h3>
                      <p className="text-[11px] text-poly-text-muted mt-0.5">Audits Performed</p>
                    </div>
                    <div className="poly-card p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="p-1.5 rounded-md bg-poly-purple/10">
                          <Database className="w-4 h-4 text-poly-purple" />
                        </div>
                        <span className="text-[10px] font-semibold text-poly-text-dim uppercase tracking-wider">Database</span>
                      </div>
                      <h3 className="text-2xl font-bold text-white font-mono">{stats.unauthorized_access}</h3>
                      <p className="text-[11px] text-poly-text-muted mt-0.5">Access Anomalies</p>
                    </div>
                  </div>

                  <div className="poly-card overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-poly-border bg-poly-panel">
                      <h3 className="text-[13px] font-semibold text-white">Recent Audit Logs</h3>
                    </div>
                    <div className="divide-y divide-poly-border">
                      {history.slice(0, 5).map((log) => (
                        <div key={log.id} className="px-4 py-2.5 flex items-center justify-between hover:bg-poly-hover transition-colors cursor-pointer" onClick={() => { setActiveTab('history'); setExpandedRow(log.id); }}>
                          <div className="flex items-center gap-3">
                            <Terminal className="w-3.5 h-3.5 text-poly-text-dim" />
                            <div>
                              <p className="text-[13px] font-medium text-poly-text">{log.target}</p>
                              <p className="text-[10px] font-mono text-poly-text-dim">{log.id.substring(0, 8)}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-4">
                            {log.score !== null ? (
                              <span className={`text-[12px] font-mono font-bold ${log.score > 80 ? 'text-poly-green' : 'text-poly-red'}`}>
                                {log.score}/100
                              </span>
                            ) : (
                              <span className={`text-[11px] font-mono font-semibold ${log.status === 'FAILED' ? 'text-poly-red' : 'text-poly-text-dim'}`}>{log.status}</span>
                            )}
                            <span className="text-[11px] text-poly-text-dim w-20 text-right">
                              {new Date(log.date).toLocaleDateString([], { month: 'short', day: 'numeric' })}
                            </span>
                          </div>
                        </div>
                      ))}
                      {history.length === 0 && (
                        <div className="p-6 text-center text-poly-text-dim text-[12px] font-mono">
                          No audit logs found
                        </div>
                      )}
                    </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'history' && !result && (
                <motion.div
                  key="history"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="space-y-6"
                >
                  <div>
                    <h2 className="text-[15px] font-semibold text-white">Scan History</h2>
                    <p className="text-poly-text-muted text-[13px] mt-0.5">Log of past security audits.</p>
                  </div>

                  <div className="poly-card overflow-hidden">
                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse">
                        <thead>
                          <tr>
                            <th className="px-4 py-2 text-[11px] font-semibold text-poly-text-dim uppercase border-b border-poly-border">ID</th>
                            <th className="px-4 py-2 text-[11px] font-semibold text-poly-text-dim uppercase border-b border-poly-border">Target</th>
                            <th className="px-4 py-2 text-[11px] font-semibold text-poly-text-dim uppercase border-b border-poly-border">Date</th>
                            <th className="px-4 py-2 text-[11px] font-semibold text-poly-text-dim uppercase border-b border-poly-border">Status</th>
                            <th className="px-4 py-2 text-[11px] font-semibold text-poly-text-dim uppercase border-b border-poly-border text-right">Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-poly-border">
                          {currentHistory.map((item) => (
                            <React.Fragment key={item.id}>
                              <tr
                                onClick={() => {
                                  const nextExpanded = expandedRow === item.id ? null : item.id;
                                  setExpandedRow(nextExpanded);
                                  if (nextExpanded) fetchHistoryDetails(item.id);
                                }}
                                className="group hover:bg-poly-hover transition-colors cursor-pointer"
                              >
                                <td className="px-4 py-3 text-[11px] font-mono text-poly-text-dim group-hover:text-poly-text-muted transition-colors">
                                  {item.id.substring(0, 8)}
                                </td>
                                <td className="px-4 py-3">
                                  <div className="flex items-center gap-2.5">
                                    <div className="p-1.5 rounded-md bg-poly-panel border border-poly-border group-hover:border-poly-border-light transition-colors">
                                      {item.type === 'url' ? <Globe className="w-3 h-3 text-poly-accent" /> : <Github className="w-3 h-3 text-poly-text-muted" />}
                                    </div>
                                    <span className="text-[13px] font-medium text-poly-text">{item.target}</span>
                                  </div>
                                </td>
                                <td className="px-4 py-3 text-[11px] font-medium text-poly-text-dim">
                                  {new Date(item.date).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                                </td>
                                <td className="px-4 py-3">
                                  <span className={`poly-badge ${item.status === 'COMPLETED' ? 'bg-poly-green/15 text-poly-green' :
                                    item.status === 'FAILED' ? 'bg-poly-red/15 text-poly-red' :
                                      'bg-poly-orange/15 text-poly-orange'
                                    }`}>
                                    {item.status}
                                  </span>
                                </td>
                                <td className="px-4 py-3 text-right">
                                  {item.score !== null ? (
                                    <span className={`text-[13px] font-bold font-mono ${item.score > 80 ? 'text-poly-green' : item.score > 50 ? 'text-poly-orange' : 'text-poly-red'}`}>
                                      {item.score}
                                    </span>
                                  ) : (
                                    <span className="text-[11px] font-bold text-poly-text-dim">-</span>
                                  )}
                                </td>
                              </tr>
                              {expandedRow === item.id && (() => {
                                const detail = historyDetails[item.id];
                                return (
                                  <tr>
                                    <td colSpan={5} className="p-0 border-b border-poly-border bg-poly-bg">
                                      <motion.div
                                        initial={{ height: 0, opacity: 0 }}
                                        animate={{ height: 'auto', opacity: 1 }}
                                        exit={{ height: 0, opacity: 0 }}
                                        className="overflow-hidden"
                                      >
                                        <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-4 border-b border-poly-border">
                                          <div className="space-y-2">
                                            <h4 className="text-[11px] font-semibold text-poly-red uppercase flex items-center gap-1.5">
                                              <AlertTriangle className="w-3 h-3" /> Critical Issues
                                            </h4>
                                            {detail?.criticalIssues?.length ? (
                                              <ul className="space-y-1.5">
                                                {detail.criticalIssues.map((issue, idx) => (
                                                  <li key={idx} className="text-[12px] text-poly-text bg-poly-red/5 border border-poly-red/10 p-2 rounded-md">{issue}</li>
                                                ))}
                                              </ul>
                                            ) : <span className="text-[11px] text-poly-text-dim">None detected</span>}
                                          </div>
                                          <div className="space-y-2">
                                            <h4 className="text-[11px] font-semibold text-poly-orange uppercase flex items-center gap-1.5">
                                              <AlertTriangle className="w-3 h-3" /> Warnings
                                            </h4>
                                            {detail?.warnings?.length ? (
                                              <ul className="space-y-1.5">
                                                {detail.warnings.map((warning, idx) => (
                                                  <li key={idx} className="text-[12px] text-poly-text bg-poly-orange/5 border border-poly-orange/10 p-2 rounded-md">{warning}</li>
                                                ))}
                                              </ul>
                                            ) : <span className="text-[11px] text-poly-text-dim">None detected</span>}
                                          </div>
                                          <div className="space-y-2">
                                            <h4 className="text-[11px] font-semibold text-poly-green uppercase flex items-center gap-1.5">
                                              <CheckCircle className="w-3 h-3" /> Recommended Fixes
                                            </h4>
                                            {detail?.fixes?.length ? (
                                              <ul className="space-y-1.5">
                                                {detail.fixes.map((fix, idx) => (
                                                  <li key={idx} className="text-[12px] text-poly-text bg-poly-green/5 border border-poly-green/10 p-2 rounded-md">{fix.description}</li>
                                                ))}
                                              </ul>
                                            ) : <span className="text-[11px] text-poly-text-dim">N/A</span>}
                                          </div>
                                        </div>

                                        {detail?.investigationSteps && detail.investigationSteps.length > 0 && (
                                          <div className="p-4 bg-poly-panel/30 border-b border-poly-border">
                                            <InvestigationTimeline steps={detail.investigationSteps} />
                                          </div>
                                        )}
                                        {!detail && (
                                          <div className="px-4 py-3 text-[11px] text-poly-text-dim font-mono">Loading scan details...</div>
                                        )}
                                        {(item.status === 'FAILED' || item.status === 'BLOCKED') && (
                                          <div className="px-4 pb-3">
                                            <button
                                              onClick={(e) => { e.stopPropagation(); handleRetry(item); }}
                                              className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium bg-poly-green/10 text-poly-green border border-poly-green/20 rounded-md hover:bg-poly-green/20 transition-colors"
                                            >
                                              <ArrowRight className="w-3 h-3" />
                                              Retry Scan
                                            </button>
                                          </div>
                                        )}
                                      </motion.div>
                                    </td>
                                  </tr>
                                );
                              })()}
                            </React.Fragment>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {/* Pagination */}
                    <div className="px-4 py-2.5 border-t border-poly-border flex items-center justify-between bg-poly-panel">
                      <span className="text-[11px] text-poly-text-dim font-mono">
                        Showing {(currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, history.length)} of {history.length}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                          disabled={currentPage === 1}
                          className="p-1 rounded-md bg-poly-bg border border-poly-border text-poly-text-muted hover:border-poly-border-light disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                        >
                          <ChevronLeft className="w-3.5 h-3.5" />
                        </button>
                        <span className="text-[11px] font-mono text-poly-text-dim px-2">
                          {currentPage}/{totalPages}
                        </span>
                        <button
                          onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                          disabled={currentPage === totalPages}
                          className="p-1 rounded-md bg-poly-bg border border-poly-border text-poly-text-muted hover:border-poly-border-light disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                        >
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {(activeTab === 'new_scan' || result) && (
                <motion.div
                  key="scan"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="max-w-6xl w-full mx-auto"
                >
                  {!result && (
                    <div className="space-y-8">
                      <div className="text-center space-y-1.5">
                        <div className="w-10 h-10 bg-poly-panel border border-poly-border rounded-md flex items-center justify-center mx-auto mb-3">
                          <Search className={`w-5 h-5 ${isScanning ? 'text-poly-accent animate-pulse' : 'text-poly-text-muted'}`} />
                        </div>
                        <h2 className="text-[17px] font-semibold text-white">
                          {isScanning ? 'Vulnerability Analysis in Progress' : 'Initiate Security Audit'}
                        </h2>
                        <p className="text-poly-text-muted text-[13px] max-w-md mx-auto">
                          {isScanning ? `Currently analyzing ${target}...` : 'Target will be analyzed safely in a secure environment.'}
                        </p>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                        <div className="lg:col-span-12 xl:col-span-8 space-y-6">
                          <form onSubmit={handleScan} className={`poly-card p-5 space-y-5 transition-opacity ${isScanning ? 'opacity-60 pointer-events-none' : ''}`}>
                            <div className="poly-segment flex">
                              <button
                                type="button"
                                disabled={isScanning}
                                onClick={() => setScanType('url')}
                                className={`poly-segment-item flex-1 flex items-center justify-center gap-2 py-1.5 text-[12px] font-medium transition-all ${scanType === 'url' ? 'active text-white' : 'text-poly-text-muted hover:text-poly-text'}`}
                              >
                                <Globe className="w-3.5 h-3.5" />
                                Website / API
                              </button>
                              <button
                                type="button"
                                disabled={isScanning}
                                onClick={() => setScanType('repo')}
                                className={`poly-segment-item flex-1 flex items-center justify-center gap-2 py-1.5 text-[12px] font-medium transition-all ${scanType === 'repo' ? 'active text-white' : 'text-poly-text-muted hover:text-poly-text'}`}
                              >
                                <Github className="w-3.5 h-3.5" />
                                Repository
                              </button>
                            </div>
                            {!isAuthenticated && scanType === 'repo' ? (
                              <div className="bg-poly-green/5 border border-poly-green/10 rounded-md p-6 text-center space-y-4">
                                <div className="w-10 h-10 bg-poly-green/10 rounded-full flex items-center justify-center mx-auto">
                                  <Github className="w-5 h-5 text-poly-green" />
                                </div>
                                <div className="space-y-1">
                                  <h3 className="text-[14px] font-medium text-white">GitHub Connection Required</h3>
                                  <p className="text-[12px] text-poly-text-muted max-w-[280px] mx-auto">
                                    Analyzing repositories requires an authenticated session.
                                  </p>
                                </div>
                                <button
                                  type="button"
                                  onClick={handleLogin}
                                  className="poly-btn-secondary inline-flex items-center gap-2 mx-auto"
                                >
                                  <Github className="w-3.5 h-3.5" /> Connect with GitHub
                                </button>
                              </div>
                            ) : (
                              <>
                                <div className="space-y-1">
                                  <label className="text-[11px] font-semibold text-poly-text-muted uppercase tracking-wider pl-0.5">
                                    {scanType === 'url' ? 'Target Website URL' : 'Repository Source'}
                                  </label>
                                  {scanType === 'url' ? (
                                    <div className="relative group">
                                      <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none text-poly-text-dim group-focus-within:text-poly-accent transition-colors">
                                        <Globe className="w-3.5 h-3.5" />
                                      </div>
                                      <input
                                        type="text"
                                        value={target}
                                        disabled={isScanning}
                                        onChange={(e) => setTarget(e.target.value)}
                                        placeholder="https://example.com"
                                        className="poly-input w-full pl-9 pr-4 text-[13px] disabled:opacity-50"
                                      />
                                    </div>
                                  ) : (
                                    <div className="space-y-2">
                                      <div className="flex items-center gap-2 p-0.5 bg-poly-bg rounded-md border border-poly-border">
                                        <button
                                          type="button"
                                          disabled={isScanning}
                                          onClick={() => setRepoInputMode('select')}
                                          className={`flex-1 py-1.5 text-[11px] font-semibold rounded transition-all ${repoInputMode === 'select' ? 'bg-poly-active text-white' : 'text-poly-text-muted hover:text-poly-text'}`}
                                        >
                                          Choose from GitHub
                                        </button>
                                        <button
                                          type="button"
                                          disabled={isScanning}
                                          onClick={() => setRepoInputMode('paste')}
                                          className={`flex-1 py-1.5 text-[11px] font-semibold rounded transition-all ${repoInputMode === 'paste' ? 'bg-poly-active text-white' : 'text-poly-text-muted hover:text-poly-text'}`}
                                        >
                                          Paste repo URL
                                        </button>
                                      </div>

                                      {repoInputMode === 'select' ? (
                                        <>
                                          <div className="relative group">
                                            <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none text-poly-text-dim group-focus-within:text-poly-accent transition-colors">
                                              <Github className="w-3.5 h-3.5" />
                                            </div>
                                            <select
                                              value={target}
                                              onChange={(e) => setTarget(e.target.value)}
                                              className="poly-input w-full pl-9 pr-4 text-[13px] disabled:opacity-50"
                                              disabled={isLoadingRepos || isScanning}
                                            >
                                              <option value="">{isLoadingRepos ? 'Loading repositories...' : 'Select a repository'}</option>
                                              {githubRepos.map((repo) => (
                                                <option key={repo.id} value={repo.full_name}>
                                                  {repo.full_name}
                                                </option>
                                              ))}
                                            </select>
                                          </div>
                                          {repoFetchError && (
                                            <p className="text-[11px] text-poly-text-dim">{repoFetchError}</p>
                                          )}
                                        </>
                                      ) : (
                                        <div className="relative group">
                                          <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none text-poly-text-dim group-focus-within:text-poly-accent transition-colors">
                                            <Github className="w-3.5 h-3.5" />
                                          </div>
                                          <input
                                            type="text"
                                            value={target}
                                            disabled={isScanning}
                                            onChange={(e) => setTarget(e.target.value)}
                                            placeholder="owner/repo or https://github.com/owner/repo"
                                            className="poly-input w-full pl-9 pr-4 text-[13px] disabled:opacity-50"
                                          />
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>


                                <div className="space-y-2">
                                  <label className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider flex items-center gap-1.5 pl-0.5">
                                    <Clock className="w-3 h-3" /> Automation Settings
                                  </label>
                                  <div className="grid grid-cols-4 gap-1.5">
                                    {['none', 'daily', 'weekly', 'monthly'].map((int) => (
                                      <button
                                        key={int}
                                        type="button"
                                        disabled={isScanning}
                                        onClick={() => setScheduledInterval(int)}
                                        className={`px-3 py-1.5 rounded-md text-[11px] font-semibold transition-all ${scheduledInterval === int
                                          ? 'bg-poly-green-dim text-white border border-poly-green/30'
                                          : 'bg-poly-bg text-poly-text-muted border border-poly-border hover:border-poly-border-light'
                                          }`}
                                      >
                                        {int === 'none' ? 'Once' : int.charAt(0).toUpperCase() + int.slice(1)}
                                      </button>
                                    ))}
                                  </div>
                                </div>

                                {error && (
                                  <div className="p-2.5 bg-poly-red/5 border border-poly-red/20 rounded-md flex items-start gap-2">
                                    <AlertTriangle className="w-4 h-4 text-poly-red shrink-0 mt-0.5" />
                                    <p className="text-[12px] text-poly-red">{error}</p>
                                  </div>
                                )}

                                <div className="space-y-3">
                                  <button
                                    type="submit"
                                    disabled={!target || isScanning}
                                    className="poly-btn-primary w-full py-2.5 text-[13px] flex items-center justify-center gap-2 rounded-[10px] disabled:opacity-40"
                                  >
                                    {isScanning ? 'Analyze Running...' : 'Start Secure Audit'}
                                    {!isScanning && <ArrowRight className="w-3.5 h-3.5 ml-1" />}
                                  </button>
                                  <div className="flex flex-col items-center gap-1">
                                    <p className="text-[10px] text-poly-text-dim font-medium">Passive Analysis • Private Compute • No Third-Party Sharing</p>
                                  </div>
                                </div>
                              </>
                            )}
                          </form>

                          <div className={`poly-card overflow-hidden transition-opacity ${isScanning ? 'opacity-40 pointer-events-none' : ''}`}>
                            <div className="px-4 py-2.5 border-b border-poly-border bg-poly-panel flex items-center justify-between">
                              <h3 className="text-[12px] font-semibold text-white">Recent Activity</h3>
                              <button onClick={() => setActiveTab('history')} className="text-[10px] text-poly-accent hover:underline font-medium">View History</button>
                            </div>
                            <div className="divide-y divide-poly-border">
                              {history.slice(0, 3).map((item) => (
                                <div key={item.id} className="px-4 py-3 flex items-center justify-between hover:bg-poly-hover transition-colors cursor-pointer" onClick={() => { setActiveTab('history'); setExpandedRow(item.id); fetchHistoryDetails(item.id); }}>
                                  <div className="flex items-center gap-3">
                                    <div className="p-1.5 rounded bg-poly-panel border border-poly-border">
                                      {item.type === 'url' ? <Globe className="w-3 h-3 text-poly-accent" /> : <Github className="w-3 h-3 text-poly-text-muted" />}
                                    </div>
                                    <div>
                                      <p className="text-[13px] font-medium text-poly-text">{item.target}</p>
                                      <p className="text-[10px] text-poly-text-dim font-mono">{new Date(item.date).toLocaleDateString()}</p>
                                    </div>
                                  </div>
                                  <span className={`poly-badge ${item.status === 'COMPLETED' ? 'bg-poly-green/15 text-poly-green' : 'bg-poly-red/15 text-poly-red'}`}>
                                    {item.status === 'COMPLETED' ? (item.score ?? 'OK') : item.status}
                                  </span>
                                </div>
                              ))}
                              {history.length === 0 && <div className="p-6 text-center text-poly-text-dim text-[12px] font-mono">No recent activity</div>}
                            </div>
                          </div>
                        </div>

                        <div className="lg:col-span-12 xl:col-span-4 space-y-4 h-full flex flex-col">
                          <div className={`poly-card rounded-tr-none rounded-br-none border-poly-accent/20 flex flex-col h-[520px] lg:h-full min-h-[400px] transition-all ${isScanning ? 'ring-1 ring-poly-accent/30 shadow-[0_0_20px_rgba(var(--poly-accent-rgb),0.05)]' : ''}`}>
                            <div className="px-4 py-2 border-b border-poly-border bg-[rgba(255,255,255,0.02)] flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Terminal className={`w-3.5 h-3.5 ${isScanning ? 'text-poly-accent animate-pulse' : 'text-poly-accent'}`} />
                                <span className="text-[10px] font-bold text-poly-text-muted uppercase tracking-wider">
                                  {isScanning ? 'Live Analysis Stream' : 'Secure Scan Terminal'}
                                </span>
                              </div>
                              {isScanning ? (
                                <div className="flex items-center gap-3">
                                  <span className="text-[10px] font-mono font-bold text-poly-accent animate-pulse uppercase tracking-tighter">
                                    {scanStatus || 'Initializing'}
                                  </span>
                                  <div className="flex gap-1">
                                    <div className="w-1 h-1 rounded-full bg-poly-accent animate-bounce" style={{ animationDelay: '0ms' }} />
                                    <div className="w-1 h-1 rounded-full bg-poly-accent animate-bounce" style={{ animationDelay: '150ms' }} />
                                    <div className="w-1 h-1 rounded-full bg-poly-accent animate-bounce" style={{ animationDelay: '300ms' }} />
                                  </div>
                                </div>
                              ) : (
                                <div className="flex gap-1.5">
                                  <div className="w-2 h-2 rounded-full bg-poly-red/20 border border-poly-red/30"></div>
                                  <div className="w-2 h-2 rounded-full bg-poly-orange/20 border border-poly-orange/30"></div>
                                  <div className="w-2 h-2 rounded-full bg-poly-green/20 border border-poly-green/30"></div>
                                </div>
                              )}
                            </div>

                            {isScanning && (
                              <div className="px-4 py-3 bg-[rgba(var(--poly-accent-rgb),0.02)] border-b border-poly-border/50">
                                <div className="flex justify-between items-center mb-1.5">
                                  <span className="text-[10px] font-semibold text-poly-text-dim uppercase tracking-wider">Overall Progress</span>
                                  <span className="text-[11px] font-bold text-poly-accent font-mono">{scanProgress}%</span>
                                </div>
                                <div className="h-1.5 w-full bg-poly-border rounded-full overflow-hidden border border-poly-border/30">
                                  <motion.div
                                    className="h-full bg-poly-accent"
                                    initial={{ width: 0 }}
                                    animate={{ width: `${scanProgress}%` }}
                                    transition={{ ease: "circOut", duration: 0.5 }}
                                  />
                                </div>
                              </div>
                            )}
                            <div
                              ref={terminalViewportRef}
                              className="scan-terminal overscroll-contain text-[12px] leading-relaxed space-y-2"
                            >
                              {scanLogs.length === 0 ? (
                                <div className="h-full flex flex-col items-center justify-center text-poly-text-dim opacity-50 space-y-2">
                                  <Cpu className="w-8 h-8 animate-pulse" />
                                  <p className="text-[11px] font-medium">System Idle — Waiting for Scan</p>
                                </div>
                              ) : (
                                scanLogs.map((log, i) => (
                                  <motion.div
                                    key={i}
                                    initial={{ opacity: 0, x: -5 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    className="flex gap-3"
                                  >
                                    <span className="text-poly-text-dim shrink-0">{new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                                    <span className={i === scanLogs.length - 1 ? 'text-poly-accent font-semibold' : 'text-poly-text-muted'}>
                                      <span className="text-poly-accent/60 mr-1">$</span>
                                      {log}
                                      {i === scanLogs.length - 1 && <span className="inline-block w-1 h-3 bg-poly-accent ml-1 animate-pulse align-middle"></span>}
                                    </span>
                                  </motion.div>
                                ))
                              )}
                            </div>
                          </div>

                          <div className="poly-panel p-4 flex items-center gap-4 bg-poly-accent/5 border-poly-accent/20">
                            <div className="p-2 rounded-lg bg-poly-accent/10 border border-poly-accent/30">
                              <ShieldCheck className="w-5 h-5 text-poly-accent" />
                            </div>
                            <div className="space-y-0.5">
                              <p className="text-[12px] font-semibold text-white">Advanced Protection</p>
                              <p className="text-[10px] text-poly-text-muted">Engines are cross-verified with verified CVE databases in real-time.</p>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center justify-center gap-4 text-[11px] text-poly-text-dim">
                        <span className="flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Secure</span>
                        <span className="flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Private Compute</span>
                        <span className="flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Private Storage</span>
                      </div>
                    </div>
                  )}


                  {result && !isScanning && (
                    <div className="space-y-8">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div>
                            <h2 className="text-[17px] font-semibold text-white">Audit Report</h2>
                            <p className="text-[11px] font-semibold text-poly-accent uppercase tracking-wider mt-0.5">{target}</p>
                          </div>
                          <div className="h-8 w-px bg-poly-border mx-2 hidden md:block"></div>
                          <div>
                            <p className="text-[9px] font-semibold text-poly-text-muted uppercase tracking-wider">Scan Status</p>
                            <div className="flex items-center gap-1.5">
                              {result.confidence && result.confidence >= 90 ? (
                                <>
                                  <CheckCircle className="w-3.5 h-3.5 text-poly-green" />
                                  <span className="text-[12px] font-bold text-poly-green">Completed</span>
                                </>
                              ) : result.score === null || (result.confidence ?? 0) < 30 ? (
                                <>
                                  <AlertTriangle className="w-3.5 h-3.5 text-poly-text-dim" />
                                  <span className="text-[12px] font-bold text-poly-text-dim">Inconclusive</span>
                                </>
                              ) : result.warnings.some(w => w.toLowerCase().includes('waf') || w.toLowerCase().includes('blocked')) ? (
                                <>
                                  <AlertTriangle className="w-3.5 h-3.5 text-poly-orange" />
                                  <span className="text-[12px] font-bold text-poly-orange">Partial (WAF interference)</span>
                                </>
                              ) : (
                                <>
                                  <AlertTriangle className="w-3.5 h-3.5 text-poly-text-dim" />
                                  <span className="text-[12px] font-bold text-poly-text-dim">Incomplete Telemetry</span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                        <button
                          onClick={() => { setResult(null); setTarget(''); }}
                          className="w-7 h-7 rounded-md poly-card flex items-center justify-center text-poly-text-muted hover:text-white transition-colors"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>

                      <div className="space-y-6">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="poly-card p-6 md:col-span-2 flex items-center justify-between">
                            <div className="space-y-0.5">
                              <p className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider">Security Score</p>
                              <div className="flex items-baseline gap-2">
                                {result.score !== null ? (
                                  <span className={`text-5xl font-bold font-mono ${result.score >= 80 ? 'text-poly-green' : result.score >= 50 ? 'text-poly-orange' : 'text-poly-red'}`}>
                                    {result.score}{result.confidence && result.confidence < 70 ? '*' : ''}
                                  </span>
                                ) : (
                                  <span className="text-5xl font-bold font-mono text-poly-text-dim">—</span>
                                )}
                                <div className="flex flex-col">
                                  {(() => {
                                    if (result.score === null) return null;
                                    const prevScan = history.find(h => h.target === target && h.status === 'COMPLETED');
                                    if (prevScan && prevScan.score !== null) {
                                      const diff = result.score - prevScan.score;
                                      if (diff === 0) return null;
                                      return (
                                        <span className={`text-[10px] font-bold ${diff > 0 ? 'text-poly-green' : 'text-poly-red'}`}>
                                          {diff > 0 ? `+${diff}` : diff}
                                        </span>
                                      );
                                    }
                                    return null;
                                  })()}
                                  <span className="text-poly-text-dim font-bold text-[11px] font-mono">/ 100</span>
                                </div>
                              </div>
                              {result.score === null && result.statusText && (
                                <p className="text-[9px] text-poly-orange font-bold mt-1 uppercase tracking-tight">
                                  {result.statusText}
                                </p>
                              )}
                            </div>
                            <div className="flex flex-col items-end gap-2 text-right">
                              <div className="space-y-0.5">
                                <p className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider">Scan Confidence</p>
                                <div className="flex items-center gap-1.5 justify-end">
                                  <p className={`text-xl font-bold font-mono ${result.confidence && result.confidence >= 80 ? 'text-poly-green' : result.confidence && result.confidence >= 60 ? 'text-poly-orange' : 'text-poly-red'}`}>
                                    {result.confidence || 0}%
                                  </p>
                                  <div className="group relative">
                                    <Info className="w-3 h-3 text-poly-text-dim cursor-help" />
                                    <div className="absolute bottom-full right-0 mb-2 p-2 bg-poly-active border border-poly-border rounded-md text-[10px] text-white w-48 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50 text-left leading-normal shadow-xl">
                                      Real-time confidence metric based on telemetry success rate and WAF interference detection.
                                    </div>
                                  </div>
                                </div>
                              </div>
                              <div className="flex gap-2 print:hidden mt-2">
                                <button onClick={handleDownloadJSON} className="poly-btn-secondary text-[10px] px-3 py-1">
                                  <FileDown className="w-3 h-3 inline mr-1" /> JSON
                                </button>
                                <button onClick={handleExportPDF} className="poly-btn-primary text-[10px] px-3 py-1">
                                  <Printer className="w-3 h-3 inline mr-1" /> PDF
                                </button>
                              </div>
                            </div>
                          </div>

                          <div className="poly-card p-5 space-y-4">
                            <div>
                              <p className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider mb-2">Scan Coverage</p>
                              <div className="space-y-2">
                                <div className="flex justify-between items-center text-[11px]">
                                  <span className="text-poly-text-dim">Checks Completed</span>
                                  <span className="text-white font-mono">{result.checksCompleted || 0} / {result.totalChecks || 8}</span>
                                </div>
                                <div className="h-2 w-full bg-poly-border rounded-full overflow-hidden border border-poly-border/50">
                                  <div
                                    className="h-full bg-poly-accent transition-all duration-1000 ease-out"
                                    style={{ width: `${((result.checksCompleted || 0) / (result.totalChecks || 8)) * 100}%` }}
                                  />
                                </div>
                              </div>
                            </div>
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-center p-2 rounded bg-poly-panel border border-poly-border">
                                <p className="text-[9px] text-poly-text-dim uppercase">Pages</p>
                                <p className="text-sm font-bold text-white font-mono">
                                  {(result.confidence ?? 0) < 30 ? 'unknown' : result.coverage?.pages === 0 ? '—' : result.coverage?.pages || 0}
                                </p>
                              </div>
                              <div className="text-center p-2 rounded bg-poly-panel border border-poly-border">
                                <p className="text-[9px] text-poly-text-dim uppercase">Endpoints</p>
                                <p className="text-sm font-bold text-white font-mono">
                                  {(result.confidence ?? 0) < 30 ? 'unknown' : result.coverage?.endpoints === 0 ? '—' : result.coverage?.endpoints || 0}
                                </p>
                              </div>
                            </div>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="poly-card p-4">
                            <h3 className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider mb-3 flex items-center justify-between">
                              <div className="flex items-center gap-1.5">
                                <Globe className="w-3 h-3 text-poly-accent" /> Attack Surface Summary
                              </div>
                              {(result.confidence ?? 0) < 30 && (
                                <span className="text-[8px] text-poly-text-dim font-normal normal-case opacity-60">Inspection Blocked</span>
                              )}
                            </h3>
                            <div className="grid grid-cols-3 gap-2">
                              <div className="space-y-0.5">
                                <span className="text-[9px] text-poly-text-dim uppercase">Forms</span>
                                <p className="text-xs font-bold text-white font-mono">
                                  {(result.confidence ?? 0) < 30 ? 'unknown' : result.coverage?.forms === 0 ? '—' : result.coverage?.forms || 0}
                                </p>
                              </div>
                              <div className="space-y-0.5">
                                <span className="text-[9px] text-poly-text-dim uppercase">Headers</span>
                                <p className="text-xs font-bold text-white font-mono">
                                  {(result.confidence ?? 0) < 30 ? 'unknown' : result.coverage?.headers === 0 ? '—' : result.coverage?.headers || 0}
                                </p>
                              </div>
                              <div className="space-y-0.5">
                                <span className="text-[9px] text-poly-text-dim uppercase">Scripts</span>
                                <p className="text-xs font-bold text-white font-mono">
                                  {(result.confidence ?? 0) < 30 ? 'unknown' : result.coverage?.scripts === 0 ? '—' : result.coverage?.scripts || 0}
                                </p>
                              </div>
                            </div>
                          </div>

                          <div className="poly-card p-4">
                            <p className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider mb-2">Vulnerability Tags</p>
                            <div className="flex flex-wrap gap-1.5">
                              {result.riskCategories.map((cat, i) => (
                                <span key={i} className="px-2 py-0.5 bg-poly-panel border border-poly-border text-poly-text-muted text-[9px] font-semibold rounded-md uppercase hover:border-poly-accent transition-colors">
                                  {cat}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div className="pt-2">
                          <div className="flex items-center justify-between mb-3">
                            <h3 className="text-[10px] font-semibold text-poly-text-muted uppercase tracking-wider flex items-center gap-1.5">
                              <ShieldCheck className="w-3.5 h-3.5 text-poly-green" /> Security Checks
                            </h3>
                            <div className="flex items-center gap-3 text-[8px] font-bold uppercase tracking-tight">
                              <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-poly-green" /> <span className="text-poly-text-dim">PASS</span></div>
                              <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-poly-orange" /> <span className="text-poly-text-dim">WARN</span></div>
                              <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-poly-red" /> <span className="text-poly-text-dim">FAIL</span></div>
                              <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-poly-text-dim" /> <span className="text-poly-text-dim">SKIPPED</span></div>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 lg:grid-cols-4 gap-1.5">
                            {(result.checklist || []).map(check => (
                              <div key={check.name} className={`group relative flex items-center justify-between p-2.5 rounded-md border transition-colors cursor-help ${check.status === 'PASS' ? 'border-poly-green/20 bg-poly-green/5 text-poly-green hover:border-poly-green/40' :
                                check.status === 'WARN' ? 'border-poly-orange/20 bg-poly-orange/5 text-poly-orange hover:border-poly-orange/40' :
                                  check.status === 'FAIL' ? 'border-poly-red/20 bg-poly-red/5 text-poly-red hover:border-poly-red/40' :
                                    'border-poly-border bg-poly-panel text-poly-text-dim'
                                }`}>
                                <div className="flex items-center gap-1.5 truncate pr-2">
                                  <span className="text-[11px] font-semibold truncate">{check.name}</span>
                                </div>
                                <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${check.status === 'PASS' ? 'bg-poly-green' :
                                  check.status === 'WARN' ? 'bg-poly-orange' :
                                    check.status === 'FAIL' ? 'bg-poly-red' :
                                      'bg-poly-text-dim'
                                  }`}></div>
                                <div className="absolute bottom-full left-0 mb-2 w-48 p-2 bg-poly-active border border-poly-border rounded-md text-[10px] leading-tight text-white opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                                  <p className="font-bold mb-1">{check.name}</p>
                                  <p className="text-poly-text-muted">{check.reason || 'Telemetry analyzed for baseline security standards.'}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                        {result.warnings.length > 0 && (
                          <div className="pt-2">
                            <h3 className="text-[10px] font-semibold text-poly-orange uppercase tracking-wider mb-3 flex items-center gap-1.5">
                              <AlertTriangle className="w-3 h-3" /> Security Warnings
                            </h3>
                            <div className="space-y-1.5">
                              {result.warnings.map((warning, i) => (
                                <div key={i} className="p-3 bg-poly-orange/5 border border-poly-orange/15 rounded-md text-[12px] text-poly-text leading-relaxed">
                                  <div className="flex gap-2">
                                    <AlertTriangle className="w-4 h-4 text-poly-orange shrink-0 mt-0.5" />
                                    <p>{warning}</p>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {result.criticalIssues.length > 0 && (
                          <div className="pt-2">
                            <h3 className="text-[10px] font-semibold text-poly-red uppercase tracking-wider mb-3 flex items-center gap-1.5">
                              <AlertTriangle className="w-3 h-3" /> Critical Issues
                            </h3>
                            <div className="grid grid-cols-1 gap-1.5">
                              {result.criticalIssues.map((issue, i) => (
                                <div key={i} className="flex items-center justify-between p-3 bg-poly-red/5 border border-poly-red/10 rounded-md">
                                  <div className="flex items-center gap-3">
                                    <span className="text-[10px] font-bold bg-poly-red/20 text-poly-red px-1.5 py-0.5 rounded uppercase">Critical</span>
                                    <span className="text-[12px] text-poly-text leading-relaxed">{issue}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        <div className="pt-2">
                          <InvestigationTimeline steps={result.investigationSteps || []} />
                        </div>

                        <div className="pt-6 border-t border-poly-border">
                          <h3 className="text-[10px] font-semibold text-poly-accent uppercase tracking-wider mb-4 flex items-center gap-1.5">
                            <CheckCircle className="w-3 h-3" /> Remediation Path
                          </h3>
                          <div className="space-y-3">
                            {(result.fixes || []).map((fix, i) => (
                              <div key={i} className="poly-card p-4 flex flex-col gap-3">
                                <div className="flex gap-3">
                                  <div className="w-5 h-5 rounded-full bg-poly-accent/10 flex items-center justify-center text-[10px] font-bold text-poly-accent shrink-0">
                                    {i + 1}
                                  </div>
                                  <div>
                                    <p className="text-[12px] font-medium text-poly-text leading-relaxed">{fix.description}</p>
                                    {fix.file && (
                                      <div className="mt-1 flex items-center gap-1.5 text-poly-text-dim">
                                        <Terminal className="w-3 h-3" />
                                        <span className="text-[10px] font-mono font-semibold">{fix.file}</span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                                {fix.codeSnippet && (
                                  <div className="ml-8 overflow-hidden rounded-md border border-poly-border bg-poly-bg p-3">
                                    <pre className="text-[11px] font-mono text-poly-text-muted leading-relaxed overflow-x-auto no-scrollbar">
                                      <code>{fix.codeSnippet}</code>
                                    </pre>
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                </motion.div>
              )}
            </AnimatePresence>

          </div>
        </div>

        {/* Bottom Status Bar */}
        <div className="h-7 border-t border-poly-border flex items-center justify-between px-4 bg-[rgba(20,20,22,0.9)] backdrop-blur text-[11px] font-mono text-poly-text-dim print:hidden">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="poly-status-dot bg-poly-green" style={{ width: '6px', height: '6px' }}></span>
              <span>Connected</span>
            </div>
            <span className="text-poly-border">|</span>
            <span>shipout Beta v0.0.8</span>
          </div>
          <div className="flex items-center gap-3">
            <span>Gateway: Ready</span>
          </div>
        </div>
      </main>
    </div>
  );
}
