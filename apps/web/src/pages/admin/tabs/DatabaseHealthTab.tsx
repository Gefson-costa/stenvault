/**
 * Admin Panel - Database Health Tab
 * Real-time database health monitoring for the unified vault database.
 *
 * @created 2026-01-19
 */
import React, { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";

import { motion } from "framer-motion";
import {
    RefreshCw,
    CheckCircle,
    XCircle,
    AlertTriangle,
    Clock,
    HardDrive,
    Activity,
    Table,
    Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

interface TableStatus {
    expected: number;
    found: number;
    missing: string[];
    extra: string[];
}

interface DatabaseStatus {
    connected: boolean;
    latencyMs: number;
    error?: string;
    tables: TableStatus;
}

interface DbCheckResponse {
    status: "healthy" | "degraded" | "unhealthy";
    timestamp: string;
    databases: {
        vault: DatabaseStatus;
    };
}

const m3Transition = {
    duration: 0.35,
    ease: [0.05, 0.7, 0.1, 1] as [number, number, number, number],
};

async function fetchDbCheck(): Promise<DbCheckResponse> {
    const response = await fetch("/api/db-check", {
        credentials: "include",
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
}

function StatusIcon({ status }: { status: "healthy" | "degraded" | "unhealthy" }) {
    if (status === "healthy") {
        return <CheckCircle className="h-5 w-5 text-teal-500" />;
    }
    if (status === "degraded") {
        return <AlertTriangle className="h-5 w-5 text-amber-500" />;
    }
    return <XCircle className="h-5 w-5 text-rose-500" />;
}

function getStatusColor(status: "healthy" | "degraded" | "unhealthy") {
    if (status === "healthy") return "text-teal-500 bg-teal-500/10 border-teal-500/20";
    if (status === "degraded") return "text-amber-500 bg-amber-500/10 border-amber-500/20";
    return "text-rose-500 bg-rose-500/10 border-rose-500/20";
}

function DatabaseCard({
    name,
    icon: Icon,
    status,
    isLoading,
}: {
    name: string;
    icon: React.ElementType;
    status: DatabaseStatus | undefined;
    isLoading: boolean;
}) {
    const connected = status?.connected ?? false;
    const latency = status?.latencyMs ?? 0;
    const tables = status?.tables;
    const error = status?.error;

    const dbStatus = !status ? "unhealthy" :
        connected && tables?.missing.length === 0 ? "healthy" :
            connected ? "degraded" : "unhealthy";

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={m3Transition}
        >
            <Card className={cn(
                "relative overflow-hidden border-white/[0.08] transition-all duration-300",
                isLoading && "animate-pulse"
            )}>
                {/* Gradient border top */}
                <div className={cn(
                    "absolute top-0 left-0 right-0 h-[2px]",
                    dbStatus === "healthy" && "bg-gradient-to-r from-transparent via-teal-500/50 to-transparent",
                    dbStatus === "degraded" && "bg-gradient-to-r from-transparent via-amber-500/50 to-transparent",
                    dbStatus === "unhealthy" && "bg-gradient-to-r from-transparent via-rose-500/50 to-transparent",
                )} />

                <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className={cn(
                                "p-2 rounded-lg",
                                getStatusColor(dbStatus)
                            )}>
                                <Icon className="h-5 w-5" />
                            </div>
                            <div>
                                <CardTitle className="text-lg">{name}</CardTitle>
                                <CardDescription className="text-xs">
                                    {connected ? "Connected" : "Disconnected"}
                                </CardDescription>
                            </div>
                        </div>
                        <StatusIcon status={dbStatus} />
                    </div>
                </CardHeader>

                <CardContent className="space-y-4">
                    {/* Connection Status */}
                    <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">Latency</span>
                        <div className="flex items-center gap-2">
                            <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                            <span className={cn(
                                "font-mono font-medium",
                                latency < 50 ? "text-teal-500" :
                                    latency < 200 ? "text-amber-500" : "text-rose-500"
                            )}>
                                {latency}ms
                            </span>
                        </div>
                    </div>

                    {/* Table Status */}
                    {tables && (
                        <>
                            <div className="space-y-2">
                                <div className="flex items-center justify-between text-sm">
                                    <span className="text-muted-foreground flex items-center gap-2">
                                        <Table className="h-3.5 w-3.5" />
                                        Tables
                                    </span>
                                    <span className="font-mono">
                                        {tables.found} / {tables.expected}
                                    </span>
                                </div>
                                <Progress
                                    value={(tables.found / tables.expected) * 100}
                                    className="h-1.5"
                                />
                            </div>

                            {tables.missing.length > 0 && (
                                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20">
                                    <p className="text-xs font-medium text-rose-400 mb-2">
                                        Missing Tables ({tables.missing.length})
                                    </p>
                                    <div className="flex flex-wrap gap-1">
                                        {tables.missing.slice(0, 5).map((table) => (
                                            <Badge
                                                key={table}
                                                variant="outline"
                                                className="text-[10px] bg-rose-500/10 border-rose-500/20 text-rose-400"
                                            >
                                                {table}
                                            </Badge>
                                        ))}
                                        {tables.missing.length > 5 && (
                                            <Badge
                                                variant="outline"
                                                className="text-[10px] bg-rose-500/10 border-rose-500/20 text-rose-400"
                                            >
                                                +{tables.missing.length - 5} more
                                            </Badge>
                                        )}
                                    </div>
                                </div>
                            )}

                            {tables.extra.length > 0 && (
                                <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                                    <p className="text-xs font-medium text-amber-400 mb-2">
                                        Extra Tables ({tables.extra.length})
                                    </p>
                                    <div className="flex flex-wrap gap-1">
                                        {tables.extra.slice(0, 5).map((table) => (
                                            <Badge
                                                key={table}
                                                variant="outline"
                                                className="text-[10px] bg-amber-500/10 border-amber-500/20 text-amber-400"
                                            >
                                                {table}
                                            </Badge>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </>
                    )}

                    {error && (
                        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20">
                            <p className="text-xs text-rose-400">{error}</p>
                        </div>
                    )}
                </CardContent>
            </Card>
        </motion.div>
    );
}

export function DatabaseHealthTab() {
    const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

    const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
        queryKey: ["db-check"],
        queryFn: fetchDbCheck,
        refetchInterval: 30000, // Auto-refresh every 30s
        staleTime: 10000,
    });

    const handleRefresh = useCallback(() => {
        refetch();
        setLastRefresh(new Date());
    }, [refetch]);

    const overallStatus = data?.status ?? "unhealthy";

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">Database Health</h2>
                    <p className="text-sm text-muted-foreground">
                        Monitor vault database integrity
                    </p>
                </div>

                <div className="flex items-center gap-3">
                    {lastRefresh && (
                        <span className="text-xs text-muted-foreground hidden sm:block">
                            Last refresh: {lastRefresh.toLocaleTimeString()}
                        </span>
                    )}
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={handleRefresh}
                        disabled={isFetching}
                        className="gap-2"
                    >
                        <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} />
                        Refresh
                    </Button>
                </div>
            </div>

            {/* Overall Status Banner */}
            <motion.div
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={m3Transition}
            >
                <Card className={cn(
                    "border-white/[0.08]",
                    getStatusColor(overallStatus)
                )}>
                    <CardContent className="py-4">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-4">
                                <div className={cn(
                                    "p-3 rounded-xl",
                                    getStatusColor(overallStatus)
                                )}>
                                    <Activity className="h-6 w-6" />
                                </div>
                                <div>
                                    <h3 className="text-lg font-semibold capitalize">{overallStatus}</h3>
                                    <p className="text-xs text-muted-foreground">
                                        {data?.timestamp ? new Date(data.timestamp).toLocaleString() : "Loading..."}
                                    </p>
                                </div>
                            </div>
                            <Badge
                                variant="outline"
                                className={cn("text-xs uppercase tracking-wider", getStatusColor(overallStatus))}
                            >
                                {overallStatus === "healthy" ? "All Systems Operational" :
                                    overallStatus === "degraded" ? "Partial Degradation" :
                                        "System Unhealthy"}
                            </Badge>
                        </div>
                    </CardContent>
                </Card>
            </motion.div>

            {/* Error State */}
            {isError && (
                <Card className="border-rose-500/20 bg-rose-500/5">
                    <CardContent className="py-4">
                        <div className="flex items-center gap-3 text-rose-400">
                            <XCircle className="h-5 w-5" />
                            <span className="text-sm">
                                Failed to fetch database status: {(error as Error)?.message}
                            </span>
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* Database Card */}
            <DatabaseCard
                name="Vault Database"
                icon={HardDrive}
                status={data?.databases.vault}
                isLoading={isLoading}
            />

            {/* Quick Stats */}
            <div className="grid gap-4 md:grid-cols-2">
                <Card className="border-white/[0.08]">
                    <CardContent className="py-4">
                        <div className="flex items-center gap-3">
                            <Zap className="h-5 w-5 text-teal-500" />
                            <div>
                                <p className="text-xs text-muted-foreground">Latency</p>
                                <p className="text-lg font-mono font-semibold">
                                    {data?.databases.vault?.latencyMs ?? "-"}ms
                                </p>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                <Card className="border-white/[0.08]">
                    <CardContent className="py-4">
                        <div className="flex items-center gap-3">
                            <Table className="h-5 w-5 text-amber-500" />
                            <div>
                                <p className="text-xs text-muted-foreground">Tables</p>
                                <p className="text-lg font-mono font-semibold">
                                    {data?.databases.vault?.tables?.found ?? "-"} / {data?.databases.vault?.tables?.expected ?? "-"}
                                </p>
                            </div>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
