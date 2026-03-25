/**
 * Admin Panel - System Monitor Tab
 * Real-time system log streaming and terminal interface
 */
import React, { useEffect, useState, useRef, useCallback } from "react";
import { io, Socket } from "socket.io-client";

import { motion, AnimatePresence } from "framer-motion";
import {
    Terminal,
    Shield,
    Database,
    MessageSquare,
    Activity,
    Search,
    Trash2,
    Play,
    Pause,
    Wifi,
    AlertTriangle
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface LogEntry {
    level: 'info' | 'error' | 'warn' | 'debug' | 'trace' | 'fatal';
    module: string;
    msg: string;
    data?: any;
    timestamp: string;
}

const MODULE_ICONS: Record<string, any> = {
    auth: Shield,
    db: Database,
    chat: MessageSquare,
    system: Activity,
    server: Wifi,
    websocket: Wifi,
    'rate-limit': Shield,
    audit: Activity,
};

const LEVEL_COLORS: Record<string, string> = {
    info: "text-teal-400",
    warn: "text-amber-400",
    error: "text-rose-500",
    debug: "text-indigo-400",
    fatal: "text-red-600 font-bold underline",
};

const MAX_LOGS = 500; // Limit history to prevent memory issues

export function SystemMonitorTab() {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [isPaused, setIsPaused] = useState(false);
    const [filterModule, setFilterModule] = useState<string>("all");
    const [filterLevel, setFilterLevel] = useState<string>("all");
    const [searchQuery, setSearchQuery] = useState("");
    const [isConnected, setIsConnected] = useState(false);
    // In production, API and web share the same origin (Railway serves both)
    // VITE_WS_URL is only needed in dev where ports differ (API:3000, Web:5173)
    const [wsUrl] = useState(() => import.meta.env.VITE_WS_URL || (import.meta.env.DEV ? "" : window.location.origin));
    const wsNotConfigured = !wsUrl;

    const socketRef = useRef<Socket | null>(null);
    const scrollRef = useRef<HTMLDivElement>(null);
    const logsRef = useRef<LogEntry[]>([]);

    // Auto-scroll to bottom
    const scrollToBottom = useCallback(() => {
        if (scrollRef.current && !isPaused) {
            const scrollContainer = scrollRef.current.querySelector('[data-radix-scroll-area-viewport]');
            if (scrollContainer) {
                scrollContainer.scrollTop = scrollContainer.scrollHeight;
            }
        }
    }, [isPaused]);

    useEffect(() => {
        if (!wsUrl) return;

        const adminSocket = io(`${wsUrl}/admin/monitor`, {
            path: "/socket.io",
            withCredentials: true,
        });

        adminSocket.on("connect", () => {
            setIsConnected(true);
            if (import.meta.env.DEV) console.log("Connected to Admin Monitor");
        });

        adminSocket.on("disconnect", () => {
            setIsConnected(false);
        });

        adminSocket.on("log:stream", (log: LogEntry) => {
            if (isPaused) return;

            logsRef.current = [...logsRef.current, log].slice(-MAX_LOGS);
            setLogs(logsRef.current);

            // Debounced scroll
            setTimeout(scrollToBottom, 50);
        });

        socketRef.current = adminSocket;

        return () => {
            adminSocket.disconnect();
        };
    }, [isPaused, scrollToBottom]);

    // Filtering logic
    const filteredLogs = logs.filter(log => {
        const matchesModule = filterModule === "all" || log.module === filterModule;
        const matchesLevel = filterLevel === "all" || log.level === filterLevel;
        const matchesSearch = !searchQuery ||
            log.msg.toLowerCase().includes(searchQuery.toLowerCase()) ||
            log.module.toLowerCase().includes(searchQuery.toLowerCase());

        return matchesModule && matchesLevel && matchesSearch;
    });

    const clearLogs = () => {
        logsRef.current = [];
        setLogs([]);
    };

    if (wsNotConfigured) {
        return (
            <div className="flex flex-col h-[calc(100vh-250px)] gap-4 items-center justify-center">
                <Card className="max-w-lg border-amber-500/20 bg-amber-500/5">
                    <CardHeader>
                        <div className="flex items-center gap-3">
                            <AlertTriangle className="h-5 w-5 text-amber-500" />
                            <CardTitle className="text-amber-400">WebSocket Not Configured</CardTitle>
                        </div>
                        <CardDescription className="text-white/50">
                            Real-time log streaming requires a WebSocket connection.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <p className="text-sm text-white/60 mb-3">
                            In development, set the <code className="px-1.5 py-0.5 rounded bg-white/10 text-amber-300 text-xs font-mono">VITE_WS_URL</code> environment variable to enable the System Monitor.
                        </p>
                        <p className="text-xs text-white/30">
                            Example: <code className="font-mono text-white/40">VITE_WS_URL=http://localhost:3000</code>
                        </p>
                    </CardContent>
                </Card>
            </div>
        );
    }

    return (
        <div className="flex flex-col h-[calc(100vh-250px)] gap-4">
            {/* Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 p-4 border rounded-xl bg-white/[0.02] border-white/[0.08]">
                <div className="flex items-center gap-3">
                    <div className="flex -space-x-px">
                        <Button
                            variant="outline"
                            size="sm"
                            className={cn("rounded-r-none", isPaused && "bg-amber-500/10 text-amber-500 border-amber-500/20")}
                            onClick={() => setIsPaused(!isPaused)}
                        >
                            {isPaused ? <Play className="h-4 w-4 mr-2" /> : <Pause className="h-4 w-4 mr-2" />}
                            {isPaused ? "Resume" : "Pause"}
                        </Button>
                        <Button
                            variant="outline"
                            size="sm"
                            className="rounded-l-none border-l-0 text-rose-400 hover:text-rose-300"
                            onClick={clearLogs}
                        >
                            <Trash2 className="h-4 w-4 mr-2" />
                            Clear
                        </Button>
                    </div>

                    <div className="h-4 w-px bg-white/[0.08]" />

                    <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Level:</span>
                        <select
                            className="bg-black/20 border border-white/10 rounded px-2 py-1 text-xs outline-none focus:border-teal-500/50"
                            value={filterLevel}
                            onChange={(e) => setFilterLevel(e.target.value)}
                        >
                            <option value="all">All Levels</option>
                            <option value="info">Info</option>
                            <option value="warn">Warning</option>
                            <option value="error">Error</option>
                            <option value="debug">Debug</option>
                        </select>
                    </div>

                    <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Module:</span>
                        <select
                            className="bg-black/20 border border-white/10 rounded px-2 py-1 text-xs outline-none focus:border-teal-500/50"
                            value={filterModule}
                            onChange={(e) => setFilterModule(e.target.value)}
                        >
                            <option value="all">All Modules</option>
                            <option value="auth">Auth</option>
                            <option value="chat">Chat</option>
                            <option value="db">Database</option>
                            <option value="system">System</option>
                            <option value="server">Server</option>
                        </select>
                    </div>
                </div>

                <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input
                        placeholder="Search logs..."
                        className="pl-9 h-8 bg-black/20 border-white/10 text-xs"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>

                <div className="flex items-center gap-2">
                    <div className={cn(
                        "h-2 w-2 rounded-full",
                        isConnected ? "bg-teal-500 animate-pulse shadow-[0_0_8px_rgba(20,184,166,0.6)]" : "bg-rose-500"
                    )} />
                    <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                        {isConnected ? "Live Stream" : "Disconnected"}
                    </span>
                </div>
            </div>

            {/* Terminal Window */}
            <Card className="flex-1 overflow-hidden border-white/[0.08] bg-[#0c0c0e] shadow-2xl relative">
                {/* Visual Glows */}
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-teal-500/30 to-transparent" />
                <div className="absolute top-0 left-0 h-full w-[1px] bg-gradient-to-b from-transparent via-teal-500/10 to-transparent" />

                <div className="flex items-center justify-between px-4 py-2 border-b border-white/[0.05] bg-white/[0.02]">
                    <div className="flex items-center gap-2">
                        <Terminal className="h-4 w-4 text-teal-500" />
                        <span className="text-[10px] font-mono font-bold tracking-tighter text-white/40 uppercase">
                            Admin_Observation_Deck_v1.0
                        </span>
                    </div>
                    <span className="text-[9px] font-mono text-white/20">
                        Buffer: {filteredLogs.length} / {MAX_LOGS}
                    </span>
                </div>

                <ScrollArea ref={scrollRef} className="h-full p-4 font-mono text-[13px] leading-relaxed">
                    <div className="space-y-1.5 pb-20">
                        {filteredLogs.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-20 text-white/10 italic">
                                <Activity className="h-10 w-10 mb-4 opacity-10" />
                                <p>Aguardando fluxo de dados do servidor...</p>
                            </div>
                        ) : (
                            <AnimatePresence initial={false}>
                                {filteredLogs.map((log, i) => {
                                    const Icon = MODULE_ICONS[log.module] || Terminal;
                                    return (
                                        <motion.div
                                            key={`${log.timestamp}-${i}`}
                                            initial={{ opacity: 0, x: -10 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            className="group flex items-start gap-3 hover:bg-white/[0.03] rounded px-2 -mx-2 transition-colors py-0.5"
                                        >
                                            <span className="text-[10px] text-white/20 min-w-[75px] pt-0.5">
                                                {new Date(log.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                            </span>

                                            <div className={cn(
                                                "flex items-center gap-1.5 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-tight h-5",
                                                "bg-white/[0.03] border border-white/[0.05] min-w-[80px] justify-center"
                                            )}>
                                                <Icon className="h-3 w-3 opacity-60" />
                                                {log.module}
                                            </div>

                                            <span className={cn("flex-1 break-all", LEVEL_COLORS[log.level] || "text-white/80")}>
                                                <span className="opacity-50 mr-2">[{log.level.toUpperCase()}]</span>
                                                {log.msg}
                                                {log.data && Object.keys(log.data).length > 1 && (
                                                    <span className="text-[11px] text-white/30 ml-2 italic">
                                                        {JSON.stringify(log.data)}
                                                    </span>
                                                )}
                                            </span>
                                        </motion.div>
                                    );
                                })}
                            </AnimatePresence>
                        )}
                    </div>
                </ScrollArea>

                {/* Terminal Scanline Effect */}
                <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.1)_50%),linear-gradient(90deg,rgba(255,0,0,0.02),rgba(0,255,0,0.01),rgba(0,0,255,0.02))] bg-[length:100%_2px,3px_100%] z-50" />
            </Card>
        </div>
    );
}
