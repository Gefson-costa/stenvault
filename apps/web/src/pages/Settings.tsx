/**
 * Settings Page
 *
 * Enhanced with Aurora Design System
 * User settings and preferences management.
 * Uses MobileSettings for mobile devices.
 */

import { useMemo, useCallback, useEffect } from "react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AuroraCard, AuroraCardContent } from "@/components/ui/aurora-card";
import { trpc } from "@/lib/trpc";
import {
  Activity,
  Building2,
  CreditCard,
  HardDrive,
  Monitor,
  ShieldCheck,
  Smartphone,
  User,
  Settings as SettingsIcon,
} from "lucide-react";
import { useIsMobile } from "@/hooks/useMobile";
import { useSearch } from "wouter";
import { MobileSettings } from "@/components/mobile-v2/pages/MobileSettings";
import { FadeIn } from "@/components/ui/animated";

import { useTheme } from "@/contexts/ThemeContext";

// Subcomponents
import { SubscriptionSettings } from "@/components/settings/SubscriptionSettings";
import { SecuritySettings } from "@/components/settings/SecuritySettings";
import { StorageSettings } from "@/components/settings/StorageSettings";
import { InterfaceSettings } from "@/components/settings/InterfaceSettings";
import { TrustedDevicesSettings } from "@/components/settings/TrustedDevicesSettings";
import { OrganizationSettings } from "@/components/settings/OrganizationSettings";
import { SystemSettings } from "@/components/settings/SystemSettings";
import { ProfileSettings } from "@/components/settings/ProfileSettings";
// Types
import type { SubscriptionData } from "@/types/settings";
// Local type for desktop tabs
type SettingsSection = "profile" | "subscription" | "security" | "interface" | "storage" | "system" | "devices" | "organizations";

export default function Settings() {
  const isMobile = useIsMobile();
  const { theme } = useTheme();

  // URL-synced tab selection
  const search = useSearch();
  const activeTab = useMemo(() => {
    const params = new URLSearchParams(search);
    return params.get("tab");
  }, [search]);

  // Show toast after Stripe checkout redirect
  useEffect(() => {
    const params = new URLSearchParams(search);
    if (params.get("success") === "true") {
      toast.success("Subscription activated!");
      const url = new URL(window.location.href);
      url.searchParams.delete("success");
      history.replaceState(null, "", url.toString());
    }
  }, [search]);

  const handleTabChange = useCallback((tab: string) => {
    const url = new URL(window.location.href);
    url.searchParams.set("tab", tab);
    history.replaceState(null, "", url.toString());
  }, []);

  // Data Fetching
  const { data: health } = trpc.settings.getSystemHealth.useQuery(undefined, { staleTime: 60_000 });
  const { data: storageStats, refetch: refetchStorage } = trpc.files.getStorageStats.useQuery();

  // Stripe Data
  const { data: subscription } = trpc.stripe.getSubscription.useQuery();
  const { data: isStripeConfigured } = trpc.stripe.isConfigured.useQuery(undefined, {
    staleTime: 300_000,
  });

  const isStripeActive = isStripeConfigured?.active === true;
  const showSubscriptionTab = isStripeActive;

  // Render section content (shared between mobile and desktop)
  const renderSectionContent = (section: SettingsSection) => {
    switch (section) {
      case "profile":
        return <ProfileSettings />;
      case "subscription":
        return (
          <SubscriptionSettings
            isAdmin={subscription?.isAdmin || false}
            subscription={subscription as SubscriptionData | undefined}
            isStripeActive={isStripeActive}
          />
        );
      case "security":
        return <SecuritySettings />;
      case "interface":
        return <InterfaceSettings />;
      case "storage":
        return <StorageSettings storageStats={storageStats} refetchStorage={refetchStorage} />;
      case "system":
        return <SystemSettings health={health} />;
      case "devices":
        return <TrustedDevicesSettings />;
      case "organizations":
        return <OrganizationSettings />;
      default:
        return null;
    }
  };

  // ═══════════════════════════════════════════════════════════════════
  // MOBILE LAYOUT - Use dedicated MobileSettings component
  // ═══════════════════════════════════════════════════════════════════
  if (isMobile) {
    return <MobileSettings />;
  }

  // ═══════════════════════════════════════════════════════════════════
  // DESKTOP LAYOUT - Tabs Pattern
  // ═══════════════════════════════════════════════════════════════════
  return (
      <div className="space-y-8 max-w-5xl mx-auto">
        <FadeIn>
          <AuroraCard variant="glass" className="relative overflow-hidden">
            {/* Theme glow decoration */}
            <div
              className="absolute -top-10 -right-10 w-28 h-28 rounded-full blur-3xl opacity-15 pointer-events-none"
              style={{ backgroundColor: theme.brand.primary }}
            />
            <AuroraCardContent className="p-5">
              <div className="flex items-center gap-3">
                <motion.div
                  className="p-2.5 rounded-xl"
                  style={{ backgroundColor: `${theme.brand.primary}15` }}
                  whileHover={{ scale: 1.05, rotate: 5 }}
                >
                  <SettingsIcon
                    className="h-5 w-5"
                    style={{ color: theme.brand.primary }}
                  />
                </motion.div>
                <div>
                  <h1 className="text-2xl md:text-3xl font-semibold tracking-tight text-foreground">
                    Settings
                  </h1>
                  <p className="text-muted-foreground">
                    Preferences and integrations
                  </p>
                </div>
              </div>
            </AuroraCardContent>
          </AuroraCard>
        </FadeIn>

        <FadeIn delay={0.1}>
          <Tabs
            value={activeTab || "profile"}
            onValueChange={handleTabChange}
            className="space-y-6"
          >
            <TabsList className="flex w-full gap-1 overflow-x-auto bg-secondary/50 p-1 rounded-xl scrollbar-none">
              <TabsTrigger
                value="profile"
                className="shrink-0 gap-2 px-3 data-[state=active]:bg-card data-[state=active]:shadow-sm rounded-lg"
              >
                <User className="w-4 h-4" />
                <span className="hidden sm:inline">Profile</span>
              </TabsTrigger>
              {showSubscriptionTab && (
                <TabsTrigger
                  value="subscription"
                  className="shrink-0 gap-2 px-3 data-[state=active]:bg-card data-[state=active]:shadow-sm rounded-lg"
                >
                  <CreditCard className="w-4 h-4" />
                  <span className="hidden sm:inline">Plan</span>
                </TabsTrigger>
              )}
              <TabsTrigger
                value="security"
                className="shrink-0 gap-2 px-3 data-[state=active]:bg-card data-[state=active]:shadow-sm rounded-lg"
              >
                <ShieldCheck className="w-4 h-4" />
                <span className="hidden sm:inline">Security</span>
              </TabsTrigger>
              <TabsTrigger
                value="interface"
                className="shrink-0 gap-2 px-3 data-[state=active]:bg-card data-[state=active]:shadow-sm rounded-lg"
              >
                <Monitor className="w-4 h-4" />
                <span className="hidden sm:inline">Interface</span>
              </TabsTrigger>
              <TabsTrigger
                value="storage"
                className="shrink-0 gap-2 px-3 data-[state=active]:bg-card data-[state=active]:shadow-sm rounded-lg"
              >
                <HardDrive className="w-4 h-4" />
                <span className="hidden sm:inline">Storage</span>
              </TabsTrigger>
              <TabsTrigger
                value="system"
                className="shrink-0 gap-2 px-3 data-[state=active]:bg-card data-[state=active]:shadow-sm rounded-lg"
              >
                <Activity className="w-4 h-4" />
                <span className="hidden sm:inline">System</span>
              </TabsTrigger>
              <TabsTrigger
                value="devices"
                className="shrink-0 gap-2 px-3 data-[state=active]:bg-card data-[state=active]:shadow-sm rounded-lg"
              >
                <Smartphone className="w-4 h-4" />
                <span className="hidden sm:inline">Devices</span>
              </TabsTrigger>
              <TabsTrigger
                value="organizations"
                className="shrink-0 gap-2 px-3 data-[state=active]:bg-card data-[state=active]:shadow-sm rounded-lg"
              >
                <Building2 className="w-4 h-4" />
                <span className="hidden sm:inline">Orgs</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="profile" className="space-y-6">
              <FadeIn>{renderSectionContent("profile")}</FadeIn>
            </TabsContent>

            {showSubscriptionTab && (
              <TabsContent value="subscription" className="space-y-6">
                <FadeIn>{renderSectionContent("subscription")}</FadeIn>
              </TabsContent>
            )}

            <TabsContent value="security" className="space-y-6">
              <FadeIn>{renderSectionContent("security")}</FadeIn>
            </TabsContent>

            <TabsContent value="interface" className="space-y-6">
              <FadeIn>{renderSectionContent("interface")}</FadeIn>
            </TabsContent>

            <TabsContent value="storage" className="space-y-6">
              <FadeIn>{renderSectionContent("storage")}</FadeIn>
            </TabsContent>

            <TabsContent value="system" className="space-y-6">
              <FadeIn>{renderSectionContent("system")}</FadeIn>
            </TabsContent>

            <TabsContent value="devices" className="space-y-6">
              <FadeIn>{renderSectionContent("devices")}</FadeIn>
            </TabsContent>

            <TabsContent value="organizations" className="space-y-6">
              <FadeIn>{renderSectionContent("organizations")}</FadeIn>
            </TabsContent>
          </Tabs>
        </FadeIn>
      </div>
  );
}

