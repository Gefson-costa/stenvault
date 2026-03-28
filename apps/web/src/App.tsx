import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Routes, Route, BrowserRouter } from "react-router-dom";
import { CookieConsentBanner } from "./components/CookieConsentBanner";
import ErrorBoundary from "./components/ErrorBoundary";
import { RouteErrorBoundary } from "./components/RouteErrorBoundary";
import { P2PErrorBoundary } from "./components/p2p/P2PErrorBoundary";
import { AuthenticatedShell } from "./components/AuthenticatedShell";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { InterfaceProvider } from "./contexts/InterfaceContext";
import { OrganizationProvider } from "./contexts/OrganizationContext";
import { EmailVerificationProvider } from "./components/email-verification";
import { trpc } from "@/lib/trpc";
import { scheduleProactiveRefresh, cancelProactiveRefresh } from "@/lib/auth";
import { lazy, Suspense, useEffect } from "react";
import { Loader2 } from "lucide-react";

// Route Guards
import { RootRedirect, AuthGuard, GuestGuard } from "./routes";

// ══════════════════════════════════════════════════════════════════════════════
// Lazy-loaded pages for better initial load performance (Code Splitting)
// Heavy pages are loaded on-demand instead of upfront
// ══════════════════════════════════════════════════════════════════════════════

// Core pages - loaded immediately (V2 Premium UI)
import Login from "./pages/LoginV2";
import Register from "./pages/RegisterV2";

// Landing Page with GSAP animations
const LandingPage = lazy(() => import("./pages/LandingPage"));

// Public pages - lazy loaded
const SharedDownload = lazy(() => import("./pages/SharedDownload"));
const Pricing = lazy(() => import("./pages/Pricing"));
const SendPage = lazy(() => import("./pages/SendPage"));
const ReceivePage = lazy(() => import("./pages/ReceivePage"));
const LocalSendPage = lazy(() => import("./pages/LocalSendPage"));
const OpsDeck = lazy(() => import("./pages/OpsDeck"));
const TermsOfService = lazy(() => import("./pages/TermsOfService"));
const PrivacyPolicy = lazy(() => import("./pages/PrivacyPolicy"));

// P2P Receive Pages - Public (need to receive files without login)
const P2PReceivePage = lazy(() => import("./components/p2p/P2PReceivePage").then(m => ({ default: m.P2PReceivePage })));
const OfflineReceivePage = lazy(() => import("./components/p2p/OfflineReceivePage").then(m => ({ default: m.OfflineReceivePage })));

// Auth pages - lazy loaded (V2 Premium UI)
const ForgotPassword = lazy(() => import("./pages/ForgotPasswordV2"));
const ResetPassword = lazy(() => import("./pages/ResetPasswordV2"));
const VerifyMagicLink = lazy(() => import("./pages/VerifyMagicLink"));
const VerifyEmail = lazy(() => import("./pages/VerifyEmail"));

// Shamir Recovery - lazy loaded (public recovery page)
const ShamirRecovery = lazy(() => import("./pages/ShamirRecovery"));

// Master Key Setup - lazy loaded (Phase 1.2 NEW_DAY onboarding, no layout)
const MasterKeySetup = lazy(() => import("./pages/MasterKeySetup"));

// Recovery Code Reset - lazy loaded (Phase 4.2 NEW_DAY recovery system)
const RecoveryCodeReset = lazy(() => import("./pages/RecoveryCodeReset"));

// Org invite acceptance - lazy loaded (AuthGuard, no DashboardLayout)
const AcceptInvitePage = lazy(() => import("./pages/AcceptInvitePage"));

// Loading fallback component
function PageLoader() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-background">
      <div className="flex flex-col items-center gap-4">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading...</p>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// Guest Route Wrapper - Uses GuestGuard (redirects logged-in users)
// ══════════════════════════════════════════════════════════════════════════════
function GuestRoute({ component: Component }: { component: React.ComponentType }) {
  return (
    <GuestGuard redirectTo="/home">
      <Component />
    </GuestGuard>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// P2P Route Wrapper - Uses P2PErrorBoundary for WebRTC/crypto errors
// ══════════════════════════════════════════════════════════════════════════════
function P2PRoute({ component: Component }: { component: React.ComponentType }) {
  return (
    <P2PErrorBoundary>
      <Component />
    </P2PErrorBoundary>
  );
}

function Router() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        {/* ════════════════════════════════════════════════════════════════
            ROOT ROUTE - Intelligent redirect based on auth status
            ════════════════════════════════════════════════════════════════ */}
        <Route path="/" element={<RootRedirect />} />

        {/* ════════════════════════════════════════════════════════════════
            AUTHENTICATION ROUTES - Guest only (logged-in users redirected)
            ════════════════════════════════════════════════════════════════ */}
        <Route path="/auth/login" element={<GuestRoute component={Login} />} />
        <Route path="/auth/register" element={<GuestRoute component={Register} />} />
        <Route path="/auth/forgot-password" element={<GuestRoute component={ForgotPassword} />} />
        <Route path="/auth/reset-password" element={<GuestRoute component={ResetPassword} />} />
        <Route path="/auth/verify" element={<VerifyMagicLink />} />
        <Route path="/auth/verify-email" element={<VerifyEmail />} />
        <Route path="/auth/recovery-code-reset" element={<RecoveryCodeReset />} />

        {/* ════════════════════════════════════════════════════════════════
            PUBLIC ROUTES - Accessible by everyone
            ════════════════════════════════════════════════════════════════ */}
        <Route path="/landing" element={<RouteErrorBoundary routeName="Landing"><LandingPage /></RouteErrorBoundary>} />
        <Route path="/s/:shareCode" element={<RouteErrorBoundary routeName="Shared Download"><SharedDownload /></RouteErrorBoundary>} />
        <Route path="/pricing" element={<RouteErrorBoundary routeName="Pricing"><Pricing /></RouteErrorBoundary>} />
        <Route path="/recover" element={<RouteErrorBoundary routeName="Recovery"><ShamirRecovery /></RouteErrorBoundary>} />
        <Route path="/send" element={<RouteErrorBoundary routeName="Send"><SendPage /></RouteErrorBoundary>} />
        <Route path="/send/local" element={<RouteErrorBoundary routeName="Local Send"><LocalSendPage /></RouteErrorBoundary>} />
        <Route path="/send/:sessionId" element={<RouteErrorBoundary routeName="Receive"><ReceivePage /></RouteErrorBoundary>} />
        <Route path="/ops-deck" element={<RouteErrorBoundary routeName="Ops Deck"><OpsDeck /></RouteErrorBoundary>} />
        <Route path="/terms" element={<RouteErrorBoundary routeName="Terms of Service"><TermsOfService /></RouteErrorBoundary>} />
        <Route path="/privacy" element={<RouteErrorBoundary routeName="Privacy Policy"><PrivacyPolicy /></RouteErrorBoundary>} />

        {/* Master Key Setup - Phase 1.2 NEW_DAY Onboarding (AuthGuard but NO layout, NO MasterKeyGuard) */}
        <Route path="/master-key-setup" element={<RouteErrorBoundary routeName="Master Key Setup"><AuthGuard><MasterKeySetup /></AuthGuard></RouteErrorBoundary>} />

        {/* Org invite acceptance (AuthGuard, no layout - simple standalone page) */}
        <Route path="/invite/:code" element={<RouteErrorBoundary routeName="Accept Invite"><AuthGuard><AcceptInvitePage /></AuthGuard></RouteErrorBoundary>} />

        {/* P2P Receive Pages - Public with P2PErrorBoundary (need to receive files without login) */}
        <Route path="/p2p/offline/:sessionId" element={<P2PRoute component={OfflineReceivePage} />} />
        <Route path="/p2p/:sessionId" element={<P2PRoute component={P2PReceivePage} />} />

        {/* 404 - explicit path */}
        <Route path="/404" element={<NotFound />} />

        {/* ════════════════════════════════════════════════════════════════
            AUTHENTICATED SHELL - Persistent layout for all protected routes.
            Sidebar/MobileShell mount ONCE; only inner content swaps.
            ════════════════════════════════════════════════════════════════ */}
        <Route path="*" element={<AuthenticatedShell />} />
      </Routes>
    </Suspense>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// AppWithUser - Contains auth query and email verification provider
// PURPOSE: Fixes race condition where auth query was outside Suspense.
// Now the query runs inside Suspense, ensuring user data is available
// before EmailVerificationProvider mounts. This prevents the edge case where
// EMAIL_NOT_VERIFIED errors occur before user query completes.
// ══════════════════════════════════════════════════════════════════════════════
function AppWithUser() {
  // Get user email for verification modal (if logged in)
  // NOTE: This query is intentionally inside Suspense to prevent race conditions
  // where EMAIL_NOT_VERIFIED errors arrive before user data is loaded.
  const { data: user } = trpc.auth.me.useQuery(undefined, {
    retry: false,
    staleTime: Infinity,
  });

  // Start proactive token refresh on page load if already authenticated
  useEffect(() => {
    if (user) {
      scheduleProactiveRefresh();
    }
    return () => cancelProactiveRefresh();
  }, [!!user]);

  return (
    <OrganizationProvider>
      <EmailVerificationProvider userEmail={user?.email}>
        <Toaster />
        <Router />
      </EmailVerificationProvider>
    </OrganizationProvider>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <ThemeProvider defaultTheme="nocturne">
          <InterfaceProvider>
            <TooltipProvider>
              <Suspense fallback={<PageLoader />}>
                <AppWithUser />
              </Suspense>
              <CookieConsentBanner />
            </TooltipProvider>
          </InterfaceProvider>
        </ThemeProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}

export default App;
