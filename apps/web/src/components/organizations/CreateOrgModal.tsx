/**
 * Create Organization Modal
 * 
 * Modal dialog for creating a new organization.
 */

import React, { useState } from "react";
import { Building2, Loader2, Lock } from "lucide-react";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Badge } from "../ui/badge";
import { useOrganizationMutations } from "../../hooks/organizations/useOrganizations";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { useNavigate } from "react-router-dom";
import { useMasterKey } from "@/hooks/useMasterKey";
import { initializeOrgVault } from "@/lib/orgVaultSetup";

interface CreateOrgModalProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess?: (orgId: number) => void;
}

export function CreateOrgModal({ open, onOpenChange, onSuccess }: CreateOrgModalProps) {
    const [name, setName] = useState("");
    const [slug, setSlug] = useState("");
    const [isAutoSlug, setIsAutoSlug] = useState(true);
    const navigate = useNavigate();

    const { createOrg } = useOrganizationMutations();
    const { getCachedKey, isUnlocked } = useMasterKey();
    const orgKeysSetup = trpc.orgKeys.setup.useMutation();

    // Plan gate
    const { data: subscription } = trpc.stripe.getSubscription.useQuery(undefined, {
        enabled: open,
        staleTime: 60000,
    });
    const maxOrgs = subscription?.isAdmin ? -1 : (subscription?.limits?.maxOrganizations ?? 0);
    const isGated = maxOrgs === 0;

    const handleNameChange = (value: string) => {
        setName(value);
        if (isAutoSlug) {
            // Auto-generate slug from name
            const generatedSlug = value
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, "-")
                .replace(/^-|-$/g, "")
                .substring(0, 50);
            setSlug(generatedSlug);
        }
    };

    const handleSlugChange = (value: string) => {
        setIsAutoSlug(false);
        // Only allow valid slug characters
        const sanitized = value.toLowerCase().replace(/[^a-z0-9-]/g, "");
        setSlug(sanitized);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!name.trim()) {
            toast.error("Organization name is required");
            return;
        }

        if (slug.length < 3) {
            toast.error("Slug must be at least 3 characters");
            return;
        }

        // Personal vault must be unlocked to wrap OMK
        const personalMK = getCachedKey();
        if (!personalMK) {
            toast.error("Please unlock your vault before creating an organization");
            return;
        }

        try {
            const result = await createOrg.mutateAsync({
                name: name.trim(),
                slug: slug.trim() || undefined,
            });

            if (result) {
                // Initialize org vault encryption (OMK + hybrid keypair)
                try {
                    await initializeOrgVault(
                        result.id,
                        personalMK,
                        orgKeysSetup.mutateAsync,
                    );
                    toast.success("Organization created with encryption enabled");
                } catch (vaultErr: any) {
                    console.warn('[OrgSetup] Vault initialization failed:', vaultErr);
                    toast.warning("Organization created, but encryption setup failed. You can retry from settings.");
                }
            }

            onOpenChange(false);
            setName("");
            setSlug("");
            setIsAutoSlug(true);

            if (onSuccess && result) {
                onSuccess(result.id);
            }
        } catch (error: any) {
            toast.error(error.message || "Failed to create organization");
        }
    };

    const handleClose = () => {
        setName("");
        setSlug("");
        setIsAutoSlug(true);
        onOpenChange(false);
    };

    return (
        <Dialog open={open} onOpenChange={handleClose}>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-primary/10">
                            <Building2 className="w-5 h-5 text-primary" />
                        </div>
                        <div>
                            <DialogTitle>Create Organization</DialogTitle>
                            <DialogDescription>
                                Create a shared workspace for your team.
                            </DialogDescription>
                        </div>
                    </div>
                </DialogHeader>

                {isGated ? (
                    <div className="py-6 space-y-4">
                        <div className="flex flex-col items-center gap-3 text-center">
                            <div className="p-3 rounded-full bg-muted">
                                <Lock className="w-6 h-6 text-muted-foreground" />
                            </div>
                            <div>
                                <p className="font-medium">Organizations require a Pro plan</p>
                                <p className="text-sm text-muted-foreground mt-1">
                                    Upgrade to create shared workspaces for your team.
                                </p>
                            </div>
                            <div className="flex gap-2 pt-2">
                                <Button variant="outline" onClick={handleClose}>
                                    Cancel
                                </Button>
                                <Button onClick={() => { handleClose(); navigate('/pricing'); }}>
                                    View plans
                                </Button>
                            </div>
                        </div>
                    </div>
                ) : (
                <form onSubmit={handleSubmit}>
                    <div className="grid gap-4 py-4">
                        <div className="grid gap-2">
                            <Label htmlFor="name">Organization Name</Label>
                            <Input
                                id="name"
                                value={name}
                                onChange={(e) => handleNameChange(e.target.value)}
                                placeholder="My Company"
                                maxLength={255}
                                autoFocus
                            />
                        </div>

                        <div className="grid gap-2">
                            <Label htmlFor="slug">
                                URL Slug
                                <span className="text-xs text-muted-foreground ml-2">
                                    (lowercase letters, numbers, hyphens)
                                </span>
                            </Label>
                            <div className="flex items-center gap-2">
                                <span className="text-sm text-muted-foreground">/org/</span>
                                <Input
                                    id="slug"
                                    value={slug}
                                    onChange={(e) => handleSlugChange(e.target.value)}
                                    placeholder="my-company"
                                    maxLength={100}
                                    className="flex-1"
                                />
                            </div>
                        </div>
                    </div>

                    <DialogFooter>
                        <Button
                            type="button"
                            variant="outline"
                            onClick={handleClose}
                            disabled={createOrg.isPending}
                        >
                            Cancel
                        </Button>
                        <Button type="submit" disabled={createOrg.isPending || orgKeysSetup.isPending || !name.trim() || !isUnlocked}>
                            {(createOrg.isPending || orgKeysSetup.isPending) ? (
                                <>
                                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                    {orgKeysSetup.isPending ? "Setting up encryption..." : "Creating..."}
                                </>
                            ) : !isUnlocked ? (
                                <>
                                    <Lock className="w-4 h-4 mr-2" />
                                    Unlock vault first
                                </>
                            ) : (
                                "Create Organization"
                            )}
                        </Button>
                    </DialogFooter>
                </form>
                )}
            </DialogContent>
        </Dialog>
    );
}

export default CreateOrgModal;
