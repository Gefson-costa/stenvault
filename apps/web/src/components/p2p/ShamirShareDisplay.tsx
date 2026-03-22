/**
 * Shamir Share Display Component
 * 
 * Displays generated Shamir shares for the sender to distribute.
 * Includes copy functionality and distribution instructions.
 */
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    Key,
    Copy,
    Check,
    Shield,
    AlertTriangle,
    Download,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
    encodeShareAsString,
    type EncodedShare
} from "@/lib/shamirSecretSharing";
import { toast } from "sonner";

interface ShamirShareDisplayProps {
    shares: EncodedShare[];
    className?: string;
}

export function ShamirShareDisplay({ shares, className }: ShamirShareDisplayProps) {
    const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

    if (shares.length === 0) {
        return null;
    }

    const threshold = shares[0]?.threshold ?? 0;
    const totalShares = shares[0]?.totalShares ?? 0;

    const copyShare = async (share: EncodedShare) => {
        const encoded = encodeShareAsString(share);
        try {
            await navigator.clipboard.writeText(encoded);
            setCopiedIndex(share.index);
            toast.success(`Share #${share.index} copied to clipboard`);
            setTimeout(() => setCopiedIndex(null), 2000);
        } catch {
            toast.error("Failed to copy");
        }
    };

    const copyAllShares = async () => {
        const allShares = shares.map(s => encodeShareAsString(s)).join("\n\n");
        try {
            await navigator.clipboard.writeText(allShares);
            toast.success("All shares copied to clipboard");
        } catch {
            toast.error("Failed to copy");
        }
    };

    const downloadShares = () => {
        const content = shares.map((s, i) =>
            `=== SHARE #${s.index} ===\n${encodeShareAsString(s)}\n`
        ).join("\n");

        const header = `SHAMIR'S SECRET SHARING
========================
Total Shares: ${totalShares}
Threshold: ${threshold} (minimum needed to decrypt)

IMPORTANT: Distribute these shares to different trusted parties.
Never store all shares in the same place!

`;

        const blob = new Blob([header + content], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `shamir-shares-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success("Shares downloaded");
    };

    return (
        <Card className={cn("bg-card/50 backdrop-blur-sm border-purple-500/30", className)}>
            <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <div className="p-2 rounded-lg bg-gradient-to-br from-purple-500/20 to-pink-500/20">
                            <Key className="h-5 w-5 text-purple-500" />
                        </div>
                        <div>
                            <CardTitle className="text-lg flex items-center gap-2">
                                Secret Shares Generated
                                <Badge variant="outline" className="text-xs">
                                    {threshold}/{totalShares}
                                </Badge>
                            </CardTitle>
                            <CardDescription>
                                Distribute these shares securely
                            </CardDescription>
                        </div>
                    </div>
                    <div className="flex gap-2">
                        <Button variant="outline" size="sm" onClick={copyAllShares}>
                            <Copy className="h-4 w-4 mr-1" />
                            Copy All
                        </Button>
                        <Button variant="outline" size="sm" onClick={downloadShares}>
                            <Download className="h-4 w-4 mr-1" />
                            Download
                        </Button>
                    </div>
                </div>
            </CardHeader>
            <CardContent className="space-y-4">
                {/* Warning */}
                <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
                    <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
                    <div className="text-sm">
                        <p className="font-medium text-amber-600">Important Security Notice</p>
                        <p className="text-amber-600/80">
                            Store each share separately. The recipient needs at least{" "}
                            <strong>{threshold}</strong> shares to decrypt the file.
                        </p>
                    </div>
                </div>

                {/* Shares list */}
                <div className="grid gap-2">
                    {shares.map((share) => {
                        const encoded = encodeShareAsString(share);
                        const isCopied = copiedIndex === share.index;

                        return (
                            <div
                                key={share.index}
                                className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border border-border/50"
                            >
                                <div className="p-1.5 rounded-md bg-purple-500/10">
                                    <Shield className="h-4 w-4 text-purple-500" />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium">
                                        Share #{share.index}
                                    </p>
                                    <p className="text-xs text-muted-foreground font-mono truncate">
                                        {encoded.substring(0, 40)}...
                                    </p>
                                </div>
                                <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyShare(share)}
                                    className={cn(
                                        "shrink-0",
                                        isCopied && "text-green-500"
                                    )}
                                >
                                    {isCopied ? (
                                        <>
                                            <Check className="h-4 w-4 mr-1" />
                                            Copied
                                        </>
                                    ) : (
                                        <>
                                            <Copy className="h-4 w-4 mr-1" />
                                            Copy
                                        </>
                                    )}
                                </Button>
                            </div>
                        );
                    })}
                </div>

                {/* Info */}
                <div className="text-xs text-muted-foreground p-3 rounded-lg bg-muted/30">
                    <p>
                        Using Shamir's Secret Sharing, your encryption key has been split into{" "}
                        <strong>{totalShares} shares</strong>. Any <strong>{threshold}</strong> of
                        these shares can reconstruct the original key.
                    </p>
                </div>
            </CardContent>
        </Card>
    );
}
