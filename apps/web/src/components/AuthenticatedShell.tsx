/**
 * AuthenticatedShell - Persistent layout shell for all protected routes.
 *
 * Composes guards + DashboardLayout once so that navigation between
 * protected routes only swaps the inner content area — sidebar, mobile
 * shell, and all guard state stay mounted.
 */
import { lazy, Suspense, useEffect } from 'react';
import { Routes, Route } from 'react-router-dom';
import { RouteErrorBoundary } from './RouteErrorBoundary';
import { P2PErrorBoundary } from './p2p/P2PErrorBoundary';
import { AdminGuard, AuthGuard, MasterKeyGuard } from '@/routes';
import DashboardLayout from './DashboardLayout';
import { ContentSpinner } from './ContentSpinner';
import NotFound from '@/pages/NotFound';
import { prefetchCoreRoutes } from '@/lib/routePrefetch';

// Lazy-loaded protected pages
const Home = lazy(() => import('@/pages/Home'));
const Dashboard = lazy(() => import('@/pages/Dashboard'));
const Drive = lazy(() => import('@/pages/Drive'));
const Shares = lazy(() => import('@/pages/Shares'));
const Chat = lazy(() => import('@/pages/Chat'));
const Settings = lazy(() => import('@/pages/Settings'));
const Trash = lazy(() => import('@/pages/Trash'));
const Favorites = lazy(() => import('@/pages/Favorites'));
const AdminPanel = lazy(() => import('@/pages/AdminPanel'));
const QuantumMesh = lazy(() => import('@/pages/QuantumMesh'));
const TransferHistory = lazy(() => import('@/pages/TransferHistory'));
const SendHistory = lazy(() => import('@/pages/SendHistory'));
const OrgManagement = lazy(() => import('@/pages/OrgManagementPage'));

export function AuthenticatedShell() {
  useEffect(() => { prefetchCoreRoutes(); }, []);

  return (
    <RouteErrorBoundary routeName="App">
      <AuthGuard>
        <MasterKeyGuard>
          <DashboardLayout>
            <Suspense fallback={<ContentSpinner />}>
              <Routes>
                <Route path="/home" element={<Home />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/drive" element={<Drive />} />
                <Route path="/trash" element={<Trash />} />
                <Route path="/favorites" element={<Favorites />} />
                <Route path="/shares" element={<Shares />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="/chat" element={<Chat />} />
                <Route path="/quantum-mesh" element={<P2PErrorBoundary><QuantumMesh /></P2PErrorBoundary>} />
                <Route path="/transfers" element={<TransferHistory />} />
                <Route path="/sends" element={<SendHistory />} />
                <Route path="/organization" element={<OrgManagement />} />
                <Route path="/admin" element={<AdminGuard><AdminPanel /></AdminGuard>} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>
          </DashboardLayout>
        </MasterKeyGuard>
      </AuthGuard>
    </RouteErrorBoundary>
  );
}
