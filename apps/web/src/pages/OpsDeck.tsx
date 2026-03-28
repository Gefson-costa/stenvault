/**
 * StenVault OpsDeck - Independent Real-Time Monitor
 * 
 * Minimalist, high-performance monitoring interface that doesn't
 * depend on the main app auth or database.
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { toast } from 'sonner';
import { formatBytes } from '@stenvault/shared';
import {
    Activity,
    Zap,
    ShieldAlert,
    Terminal,
    ArrowUpCircle,
    ArrowDownCircle,
    Clock,
    Cpu,
    HardDrive,
    Lock,
    Users,
    RefreshCw
} from 'lucide-react';

interface PulseEvent {
    type: 'error' | 'traffic' | 'chat' | 'system' | 'auth';
    severity: 'info' | 'warn' | 'error' | 'critical';
    source: string;
    message: string;
    data?: Record<string, unknown>;
    timestamp: string;
}

interface SystemMetrics {
    cpu: { usage: number; cores: number };
    memory: { used: number; total: number; percentage: number; rss: number };
    uptime: { process: number; system: number };
    eventLoop: { lag: number };
    connections: { active: number };
}

export default function OpsDeck() {
    const [secret, setSecret] = useState('');
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isConnecting, setIsConnecting] = useState(false);
    const [events, setEvents] = useState<PulseEvent[]>([]);
    const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
    const [stats, setStats] = useState({
        errors: 0,
        uploads: 0,
        downloads: 0,
        chats: 0,
    });
    const [lastHeartbeat, setLastHeartbeat] = useState<Date | null>(null);
    const abortRef = useRef<AbortController | null>(null);

    const getStatusColor = useCallback(() => {
        if (!metrics) return 'text-gray-500';
        if (metrics.cpu.usage > 80 || metrics.memory.percentage > 90) return 'text-rose-500';
        if (metrics.cpu.usage > 50 || metrics.memory.percentage > 70) return 'text-amber-500';
        return 'text-green-500';
    }, [metrics]);

    const getStatusText = useCallback(() => {
        if (!metrics) return 'CONNECTING...';
        if (metrics.cpu.usage > 80 || metrics.memory.percentage > 90) return 'CRITICAL';
        if (metrics.cpu.usage > 50 || metrics.memory.percentage > 70) return 'WARNING';
        return 'OPTIMAL';
    }, [metrics]);

    const formatUptime = (seconds: number) => {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    };

    const connect = useCallback(() => {
        abortRef.current?.abort();
        setIsConnecting(true);

        const apiUrl = import.meta.env.VITE_API_URL || '';
        const controller = new AbortController();
        abortRef.current = controller;

        // fetch-based SSE: sends secret via header instead of URL query string
        (async () => {
            try {
                const res = await fetch(`${apiUrl}/api/ops/pulse`, {
                    headers: { 'x-ops-secret': secret },
                    signal: controller.signal,
                });

                if (!res.ok || !res.body) {
                    toast.error('Connection failed. Incorrect secret?');
                    setIsConnecting(false);
                    setIsAuthenticated(false);
                    return;
                }

                sessionStorage.setItem('ops_secret', secret);
                const reader = res.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    buffer += decoder.decode(value, { stream: true });
                    const parts = buffer.split('\n\n');
                    buffer = parts.pop() || '';

                    for (const part of parts) {
                        const eventMatch = part.match(/^event: (.+)$/m);
                        const dataMatch = part.match(/^data: (.+)$/m);
                        if (!eventMatch || !dataMatch) continue;

                        const eventType = eventMatch[1]!;
                        const data = JSON.parse(dataMatch[1]!);

                        if (eventType === 'history') {
                            const history = data as PulseEvent[];
                            setEvents(history);
                            setIsAuthenticated(true);
                            setIsConnecting(false);
                            const initialStats = history.reduce((acc: typeof stats, event: PulseEvent) => ({
                                errors: acc.errors + (event.type === 'error' || event.severity === 'error' || event.severity === 'critical' ? 1 : 0),
                                uploads: acc.uploads + (event.data?.direction === 'up' ? 1 : 0),
                                downloads: acc.downloads + (event.data?.direction === 'down' ? 1 : 0),
                                chats: acc.chats + (event.type === 'chat' ? 1 : 0),
                            }), { errors: 0, uploads: 0, downloads: 0, chats: 0 });
                            setStats(initialStats);
                        } else if (eventType === 'metrics') {
                            setMetrics(data as SystemMetrics);
                        } else if (eventType === 'pulse') {
                            const newEvent = data as PulseEvent;
                            setEvents(prev => [newEvent, ...prev].slice(0, 100));
                            setStats(prev => ({
                                errors: (newEvent.type === 'error' || newEvent.severity === 'error' || newEvent.severity === 'critical') ? prev.errors + 1 : prev.errors,
                                uploads: newEvent.data?.direction === 'up' ? prev.uploads + 1 : prev.uploads,
                                downloads: newEvent.data?.direction === 'down' ? prev.downloads + 1 : prev.downloads,
                                chats: newEvent.type === 'chat' ? prev.chats + 1 : prev.chats,
                            }));
                        } else if (eventType === 'heartbeat') {
                            setLastHeartbeat(new Date(data));
                        }
                    }
                }
            } catch (err: unknown) {
                if ((err as Error).name !== 'AbortError') {
                    toast.error('Connection lost');
                    setIsAuthenticated(false);
                }
            } finally {
                setIsConnecting(false);
            }
        })();
    }, [secret]);

    useEffect(() => {
        const savedSecret = sessionStorage.getItem('ops_secret');
        if (savedSecret) {
            setSecret(savedSecret);
        }
        return () => {
            abortRef.current?.abort();
        };
    }, []);

    if (!isAuthenticated) {
        return (
            <div className="min-h-screen bg-[#050505] text-white flex items-center justify-center p-6 font-mono">
                <div className="max-w-md w-full space-y-8 border border-white/10 p-8 rounded-2xl bg-white/[0.02]">
                    <div className="flex flex-col items-center">
                        <Lock className="h-12 w-12 text-teal-500 mb-4 animate-pulse" />
                        <h1 className="text-xl font-bold tracking-tighter uppercase">StenVault Ops-Deck</h1>
                        <p className="text-xs text-white/40 mt-2">Mission Critical Out-of-Band Monitor</p>
                    </div>
                    <div className="space-y-4">
                        <input
                            type="password"
                            placeholder="ENTER OPS SECRET"
                            className="w-full bg-black border border-white/20 rounded-lg p-3 text-center text-teal-400 outline-none focus:border-teal-500 transition-colors"
                            value={secret}
                            onChange={(e) => setSecret(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && connect()}
                        />
                        <button
                            onClick={connect}
                            disabled={isConnecting}
                            className="w-full bg-teal-600 hover:bg-teal-500 disabled:bg-teal-800 text-black font-bold p-3 rounded-lg transition-colors uppercase text-sm flex items-center justify-center gap-2"
                        >
                            {isConnecting && <RefreshCw className="h-4 w-4 animate-spin" />}
                            {isConnecting ? 'Establishing...' : 'Establish Connection'}
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-[#020202] text-white font-mono p-4 selection:bg-teal-500 selection:text-black">
            {/* Header / Radar Stats */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                <StatCard label="Critical Errors" value={stats.errors} color="text-rose-500" icon={ShieldAlert} />
                <StatCard label="Uploads" value={stats.uploads} color="text-teal-400" icon={ArrowUpCircle} />
                <StatCard label="Downloads" value={stats.downloads} color="text-blue-400" icon={ArrowDownCircle} />
                <StatCard label="Chat Pulse" value={stats.chats} color="text-purple-400" icon={Zap} />
                <StatCard label="Sys Health" value={getStatusText()} color={getStatusColor()} icon={Activity} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[calc(100vh-180px)]">
                {/* Event Stream (The Radar) */}
                <div className="lg:col-span-2 border border-white/10 rounded-xl bg-white/[0.02] flex flex-col overflow-hidden">
                    <div className="bg-white/[0.03] px-4 py-2 border-b border-white/10 flex justify-between items-center">
                        <div className="flex items-center gap-2">
                            <Terminal className="h-4 w-4 text-teal-500" />
                            <span className="text-xs font-bold uppercase tracking-widest">Live Event Radar</span>
                        </div>
                        <div className="flex items-center gap-3">
                            {lastHeartbeat && (
                                <span className="text-[10px] text-white/30">
                                    Last pulse: {lastHeartbeat.toLocaleTimeString()}
                                </span>
                            )}
                            <div className="h-2 w-2 rounded-full bg-green-500 animate-ping" />
                        </div>
                    </div>

                    <div className="flex-1 overflow-y-auto p-4 space-y-2 scrollbar-hide">
                        {events.length === 0 && (
                            <div className="h-full flex items-center justify-center opacity-20 italic">Awaiting pulses...</div>
                        )}
                        {events.map((ev, i) => (
                            <div key={i} className={`text-xs border-l-2 pl-3 py-1 ${ev.severity === 'critical' ? 'border-rose-600 bg-rose-500/5' :
                                ev.severity === 'error' ? 'border-rose-400' :
                                    ev.type === 'traffic' ? 'border-blue-500' :
                                        ev.type === 'auth' ? 'border-amber-500' : 'border-teal-500/30'
                                }`}>
                                <div className="flex justify-between items-start opacity-40 mb-1">
                                    <span className="text-[10px] tracking-tighter">
                                        {new Date(ev.timestamp).toLocaleTimeString()} · {ev.source.toUpperCase()}
                                    </span>
                                    <span className="text-[9px] uppercase font-bold">{ev.type}</span>
                                </div>
                                <div className={ev.severity === 'critical' ? 'text-rose-500 font-bold' : ''}>
                                    {ev.message}
                                </div>
                                {ev.data && (
                                    <pre className="mt-1 opacity-40 text-[10px] bg-black/40 p-1 rounded overflow-hidden">
                                        {JSON.stringify(ev.data, null, 2)}
                                    </pre>
                                )}
                            </div>
                        ))}
                    </div>
                </div>

                {/* System Metrics Panel */}
                <div className="space-y-6">
                    {/* Real-time Metrics */}
                    <div className="border border-white/10 rounded-xl bg-[#080808] p-4">
                        <div className="flex items-center gap-2 mb-4 opacity-50">
                            <Cpu className="h-4 w-4" />
                            <span className="text-xs font-bold uppercase">System Resources</span>
                        </div>
                        <div className="space-y-6">
                            <ResourceBar
                                label="CPU LOAD"
                                value={metrics?.cpu.usage ?? 0}
                                suffix={metrics ? `(${metrics.cpu.cores} cores)` : ''}
                            />
                            <ResourceBar
                                label="MEMORY (System)"
                                value={metrics?.memory.percentage ?? 0}
                                suffix={metrics ? formatBytes(metrics.memory.used) : ''}
                            />
                            <ResourceBar
                                label="EVENT LOOP LAG"
                                value={Math.min(100, (metrics?.eventLoop.lag ?? 0) / 10)}
                                suffix={metrics ? `${metrics.eventLoop.lag}ms` : ''}
                            />
                        </div>
                    </div>

                    {/* Status Info */}
                    <div className="border border-white/10 rounded-xl bg-white/[0.02] p-4">
                        <div className="flex items-center gap-2 mb-4 opacity-50">
                            <HardDrive className="h-4 w-4" />
                            <span className="text-xs font-bold uppercase">Server Status</span>
                        </div>
                        <div className="space-y-3">
                            <StatusRow
                                icon={Clock}
                                label="Process Uptime"
                                value={metrics ? formatUptime(metrics.uptime.process) : '--'}
                            />
                            <StatusRow
                                icon={Users}
                                label="Active Monitors"
                                value={metrics?.connections.active?.toString() ?? '0'}
                            />
                            <StatusRow
                                icon={HardDrive}
                                label="Heap Memory"
                                value={metrics ? formatBytes(metrics.memory.rss) : '--'}
                            />
                        </div>
                    </div>
                </div>
            </div>

            <div className="fixed bottom-4 right-4 text-[10px] opacity-20 font-mono italic">
                StenVault OpsDeck • Real-Time Monitor
            </div>
        </div>
    );
}

interface StatCardProps {
    label: string;
    value: string | number;
    color: string;
    icon: React.ComponentType<{ className?: string }>;
}

function StatCard({ label, value, color, icon: Icon }: StatCardProps) {
    return (
        <div className="border border-white/10 rounded-xl bg-white/[0.02] p-4 flex flex-col justify-between">
            <div className="flex items-center gap-2 opacity-50 mb-2">
                <Icon className="h-3 w-3" />
                <span className="text-[10px] font-bold uppercase tracking-wider">{label}</span>
            </div>
            <div className={`text-2xl font-bold tracking-tighter ${color}`}>
                {value}
            </div>
        </div>
    );
}

function ResourceBar({ label, value, suffix }: { label: string; value: number; suffix?: string }) {
    const color = value > 80 ? 'bg-rose-500' : value > 50 ? 'bg-amber-500' : 'bg-teal-500';

    return (
        <div className="space-y-1.5">
            <div className="flex justify-between text-[10px]">
                <span className="opacity-50">{label}</span>
                <span className="font-bold">
                    {Math.round(value)}%
                    {suffix && <span className="opacity-50 ml-2">{suffix}</span>}
                </span>
            </div>
            <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
                <div
                    className={`h-full ${color} transition-all duration-1000`}
                    style={{ width: `${Math.min(100, value)}%` }}
                />
            </div>
        </div>
    );
}

interface StatusRowProps {
    icon: React.ComponentType<{ className?: string }>;
    label: string;
    value: string;
}

function StatusRow({ icon: Icon, label, value }: StatusRowProps) {
    return (
        <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 opacity-50">
                <Icon className="h-3 w-3" />
                <span className="text-[10px]">{label}</span>
            </div>
            <span className="text-xs font-bold text-teal-400">{value}</span>
        </div>
    );
}

