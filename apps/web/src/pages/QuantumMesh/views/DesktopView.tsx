/**
 * Desktop View Component
 * Desktop-optimized layout for Quantum Mesh Dashboard
 */
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { P2PConnectionStatus } from "@/components/p2p";
import {
    Network,
    Wifi,
    CloudDownload,
    CheckCircle2,
    ArrowRightLeft,
    Zap,
    FileDown,
} from "lucide-react";
import type { ViewProps } from "../types";
import {
    StatsCard,
    ActiveTransfers,
    PendingTransfers,
    ResumableTransfers,
    TransferHistory,
    FeatureDisabled,
    SecurityBanner,
} from "../components";

export function DesktopView({ isEnabled, sessions, pendingTransfers, stats, isLoading, onRefresh }: ViewProps) {
    if (!isEnabled) {
        return <FeatureDisabled />;
    }

    return (
            <div className="container max-w-7xl mx-auto py-6 space-y-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold flex items-center gap-3">
                            <div className="p-2 rounded-xl bg-gradient-to-br from-purple-500/20 to-blue-500/20">
                                <Network className="h-8 w-8 text-purple-500" />
                            </div>
                            Quantum Mesh Network
                        </h1>
                        <p className="text-muted-foreground mt-1">
                            End-to-end encrypted peer-to-peer file transfers
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <P2PConnectionStatus
                            status="connected"
                        />
                    </div>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatsCard
                        title="Total Transfers"
                        value={stats.total}
                        description="All time"
                        icon={<ArrowRightLeft className="h-5 w-5" />}
                    />
                    <StatsCard
                        title="Active Now"
                        value={stats.active}
                        description="In progress"
                        icon={<Zap className="h-5 w-5" />}
                    />
                    <StatsCard
                        title="Pending"
                        value={stats.pending}
                        description="Waiting for you"
                        icon={<CloudDownload className="h-5 w-5" />}
                    />
                    <StatsCard
                        title="Completed"
                        value={stats.completed}
                        description="Successfully transferred"
                        icon={<CheckCircle2 className="h-5 w-5" />}
                    />
                </div>

                {/* Main Content */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Active Transfers - 2 columns */}
                    <div className="lg:col-span-2">
                        <Card className="bg-card/50 backdrop-blur-sm border-border/50">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Wifi className="h-5 w-5 text-purple-500" />
                                    Active Transfers
                                </CardTitle>
                                <CardDescription>
                                    Real-time peer-to-peer file transfers in progress
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <ActiveTransfers
                                    sessions={sessions}
                                    isLoading={isLoading}
                                    onRefresh={onRefresh}
                                />
                            </CardContent>
                        </Card>
                    </div>

                    {/* Pending Transfers - 1 column */}
                    <div className="col-span-1">
                        <Card className="bg-card/50 backdrop-blur-sm border-border/50">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <CloudDownload className="h-5 w-5 text-green-500" />
                                    Pending for You
                                    {stats.pending > 0 && (
                                        <Badge className="ml-2 bg-purple-500">
                                            {stats.pending}
                                        </Badge>
                                    )}
                                </CardTitle>
                                <CardDescription>
                                    Files waiting to be downloaded
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <PendingTransfers
                                    transfers={pendingTransfers}
                                    isLoading={isLoading}
                                />
                            </CardContent>
                        </Card>
                    </div>
                </div>

                {/* Resumable Transfers (Interrupted P2P) */}
                <ResumableTransfers />

                {/* Transfer History */}
                <Card className="bg-card/50 backdrop-blur-sm border-border/50">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <FileDown className="h-5 w-5 text-blue-500" />
                            Transfer History
                        </CardTitle>
                        <CardDescription>
                            Recently completed, failed, or expired transfers
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <TransferHistory
                            sessions={sessions}
                            isLoading={isLoading}
                        />
                    </CardContent>
                </Card>

                {/* Security Features Banner */}
                <SecurityBanner />
            </div>
    );
}
