/**
 * Admin Panel - Dialogs
 * All dialog components for admin actions
 */
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
    AlertTriangle,
    UserCheck,
    ShieldCheck,
} from "lucide-react";
import { LimitForm } from "../hooks/useAdminQueries";

// ===== Edit Limits Dialog =====
interface EditLimitsDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    selectedUser: any;
    limitForm: LimitForm;
    setLimitForm: (form: LimitForm) => void;
    onSave: () => void;
    isPending: boolean;
}

export function EditLimitsDialog({
    open,
    onOpenChange,
    selectedUser,
    limitForm,
    setLimitForm,
    onSave,
    isPending,
}: EditLimitsDialogProps) {
    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Edit User Limits</DialogTitle>
                    <DialogDescription>
                        Adjust storage quota and upload limits for {selectedUser?.name}
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                    <div className="grid gap-2">
                        <Label htmlFor="quota">Storage Quota (GB)</Label>
                        <Input
                            id="quota"
                            type="number"
                            value={limitForm.storageQuota}
                            onChange={(e) => setLimitForm({ ...limitForm, storageQuota: parseInt(e.target.value) || 0 })}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="maxSize">Max File Size (MB)</Label>
                        <Input
                            id="maxSize"
                            type="number"
                            value={limitForm.maxFileSize}
                            onChange={(e) => setLimitForm({ ...limitForm, maxFileSize: parseInt(e.target.value) || 0 })}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="maxShares">Max Shares</Label>
                        <Input
                            id="maxShares"
                            type="number"
                            value={limitForm.maxShares}
                            onChange={(e) => setLimitForm({ ...limitForm, maxShares: parseInt(e.target.value) || 0 })}
                        />
                        <p className="text-xs text-muted-foreground">Maximum number of file shares this user can create</p>
                    </div>

                    {/* Stripe Sync Protection */}
                    <div className="flex items-start space-x-3 p-4 rounded-lg bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-800">
                        <Checkbox
                            id="hasCustomQuotas"
                            checked={limitForm.hasCustomQuotas}
                            onCheckedChange={(checked) => setLimitForm({ ...limitForm, hasCustomQuotas: !!checked })}
                        />
                        <div className="grid gap-1.5 leading-none">
                            <label
                                htmlFor="hasCustomQuotas"
                                className="text-sm font-medium leading-none cursor-pointer flex items-center gap-2"
                            >
                                <ShieldCheck className="h-4 w-4 text-purple-600" />
                                Protect quotas from Stripe
                            </label>
                            <p className="text-xs text-muted-foreground">
                                When enabled, Stripe will not overwrite these quotas when the subscription changes.
                                {selectedUser?.subscriptionPlan && selectedUser.subscriptionPlan !== "free" && (
                                    <span className="block mt-1 text-amber-600 dark:text-amber-400">
                                        This user has an active {selectedUser.subscriptionPlan.toUpperCase()} plan.
                                    </span>
                                )}
                            </p>
                        </div>
                    </div>
                </div>
                <DialogFooter>
                    <Button variant="outline" onClick={() => onOpenChange(false)}>
                        Cancel
                    </Button>
                    <Button
                        onClick={onSave}
                        disabled={isPending}
                    >
                        {isPending ? "Saving..." : "Save Changes"}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

// ===== Delete User Dialog =====
interface DeleteUserDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    selectedUser: any;
    onDelete: () => void;
    isPending: boolean;
}

export function DeleteUserDialog({
    open,
    onOpenChange,
    selectedUser,
    onDelete,
    isPending,
}: DeleteUserDialogProps) {
    return (
        <AlertDialog open={open} onOpenChange={onOpenChange}>
            <AlertDialogContent>
                <AlertDialogHeader>
                    <AlertDialogTitle className="text-destructive flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5" />
                        Delete User Account
                    </AlertDialogTitle>
                    <AlertDialogDescription>
                        Are you sure you want to delete <strong>{selectedUser?.name}</strong>?
                        This action is irreversible and will delete all their files, folders, and shares.
                    </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                        onClick={onDelete}
                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        disabled={isPending}
                    >
                        {isPending ? "Deleting..." : "Delete User"}
                    </AlertDialogAction>
                </AlertDialogFooter>
            </AlertDialogContent>
        </AlertDialog>
    );
}

// ===== Change Role/Plan Dialog =====
interface ChangeRoleDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    selectedUser: any;
    selectedPlan: "free" | "pro" | "business" | "admin";
    onPlanChange: (plan: "free" | "pro" | "business" | "admin") => void;
    onConfirm: () => void;
    isPending: boolean;
}

export function ChangeRoleDialog({
    open,
    onOpenChange,
    selectedUser,
    selectedPlan,
    onPlanChange,
    onConfirm,
    isPending,
}: ChangeRoleDialogProps) {
    const getPlanLabel = (plan: string) => {
        switch (plan) {
            case "admin": return "Administrator";
            case "business": return "Business";
            case "pro": return "Pro";
            case "free": return "Free";
            default: return plan;
        }
    };

    const getPlanColor = (plan: string) => {
        switch (plan) {
            case "admin": return "text-purple-600 bg-purple-100 dark:bg-purple-900/30";
            case "business": return "text-teal-600 bg-teal-100 dark:bg-teal-900/30";
            case "pro": return "text-blue-600 bg-blue-100 dark:bg-blue-900/30";
            case "free": return "text-gray-600 bg-gray-100 dark:bg-gray-800";
            default: return "";
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <UserCheck className="h-5 w-5 text-blue-500" />
                        Change User Plan
                    </DialogTitle>
                    <DialogDescription>
                        Update role and subscription plan for <strong>{selectedUser?.name}</strong>
                    </DialogDescription>
                </DialogHeader>
                <div className="py-4 space-y-4">
                    <div className="space-y-2">
                        <Label>Select Plan</Label>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                            {(["free", "pro", "business", "admin"] as const).map((plan) => (
                                <button
                                    key={plan}
                                    type="button"
                                    onClick={() => onPlanChange(plan)}
                                    className={`p-3 rounded-lg border-2 transition-all ${selectedPlan === plan
                                            ? `border-primary ${getPlanColor(plan)}`
                                            : "border-border hover:border-muted-foreground/50"
                                        }`}
                                >
                                    <span className="text-sm font-medium">{getPlanLabel(plan)}</span>
                                </button>
                            ))}
                        </div>
                    </div>

                    {selectedPlan === "admin" && (
                        <div className="p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800">
                            <p className="text-sm text-yellow-700 dark:text-yellow-300">
                                Admin users have full access to the system including user management and settings.
                            </p>
                        </div>
                    )}

                    {selectedPlan === "pro" && (
                        <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800">
                            <p className="text-sm text-blue-700 dark:text-blue-300">
                                Pro users get: Secure Vault, Priority Support, and increased storage limits.
                            </p>
                        </div>
                    )}

                    {selectedPlan === "business" && (
                        <div className="p-3 rounded-lg bg-teal-50 dark:bg-teal-900/20 border border-teal-200 dark:border-teal-800">
                            <p className="text-sm text-teal-700 dark:text-teal-300">
                                Business users get: Per-seat billing, team management, priority support, and maximum storage.
                            </p>
                        </div>
                    )}
                </div>
                <DialogFooter>
                    <Button variant="outline" onClick={() => onOpenChange(false)}>
                        Cancel
                    </Button>
                    <Button
                        onClick={onConfirm}
                        disabled={isPending}
                        className={selectedPlan === "admin" ? "bg-purple-600 hover:bg-purple-700" : ""}
                    >
                        {isPending ? "Updating..." : "Update Plan"}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

// ===== Flush Cache Dialog =====
interface FlushCacheDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onConfirm: () => void;
    isPending: boolean;
}

export function FlushCacheDialog({
    open,
    onOpenChange,
    onConfirm,
    isPending,
}: FlushCacheDialogProps) {
    return (
        <AlertDialog open={open} onOpenChange={onOpenChange}>
            <AlertDialogContent>
                <AlertDialogHeader>
                    <AlertDialogTitle className="text-destructive flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5" />
                        Flush All Caches
                    </AlertDialogTitle>
                    <AlertDialogDescription>
                        Are you sure you want to flush all application caches?
                        <span className="block mt-2 text-muted-foreground">
                            This will clear all cached data including folder structures, user data, and other
                            frequently accessed information. The application may be slower temporarily as
                            caches rebuild.
                        </span>
                    </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                        onClick={onConfirm}
                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        disabled={isPending}
                    >
                        {isPending ? "Flushing..." : "Flush All Caches"}
                    </AlertDialogAction>
                </AlertDialogFooter>
            </AlertDialogContent>
        </AlertDialog>
    );
}
