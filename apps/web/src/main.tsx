import { trpc } from "@/lib/trpc";
import { queryClient } from "@/lib/queryClient";
import { clearAllTokens, refreshSession } from "@/lib/auth";
import { UNAUTHED_ERR_MSG } from '@shared/const';
import { QueryClientProvider } from "@tanstack/react-query";
import { httpBatchLink, TRPCClientError } from "@trpc/client";
import { createRoot } from "react-dom/client";
import superjson from "superjson";
import App from "./App";
import "./index.css";

// ═══════════════════════════════════════════════════════════════════════════════
// CSRF Token Management with TTL
// ═══════════════════════════════════════════════════════════════════════════════

const CSRF_HEADER_NAME = "x-csrf-token";
const CSRF_TOKEN_TTL_MS = 45 * 60 * 1000;

let csrfToken: string | null = null;
let csrfTokenExpiry: number | null = null;
let csrfTokenPromise: Promise<string> | null = null;

async function getCSRFToken(): Promise<string> {
  const now = Date.now();

  if (csrfToken && csrfTokenExpiry && now < csrfTokenExpiry) {
    return csrfToken;
  }

  if (csrfTokenPromise) {
    return csrfTokenPromise;
  }

  csrfTokenPromise = fetch("/api/csrf-token", {
    credentials: "include",
  })
    .then(async (res) => {
      if (!res.ok) {
        throw new Error("Failed to fetch CSRF token");
      }
      const data = await res.json();
      csrfToken = data.csrfToken;
      csrfTokenExpiry = Date.now() + CSRF_TOKEN_TTL_MS;
      return csrfToken!;
    })
    .finally(() => {
      csrfTokenPromise = null;
    });

  return csrfTokenPromise;
}

export async function refreshCSRFToken(): Promise<void> {
  csrfToken = null;
  csrfTokenExpiry = null;
  await getCSRFToken();
}

/** Track whether a silent refresh is already in progress */
let isRefreshingSession = false;

const redirectToLoginIfUnauthorized = async (error: unknown) => {
  if (!(error instanceof TRPCClientError)) return;
  if (typeof window === "undefined") return;

  const isUnauthorized = error.message === UNAUTHED_ERR_MSG;
  const isEmailNotVerified = error.message === "EMAIL_NOT_VERIFIED" || error.message.includes("EMAIL_NOT_VERIFIED");

  if (isUnauthorized) {
    const path = window.location.pathname;
    const publicPrefixes = ['/send', '/s/', '/landing', '/pricing', '/recover', '/p2p/', '/ops-deck', '/terms', '/privacy', '/auth/'];
    if (publicPrefixes.some(p => path === p || path.startsWith(p))) return;

    // Try silent refresh before logging out (access cookie expired but refresh cookie may be valid)
    if (!isRefreshingSession) {
      isRefreshingSession = true;
      try {
        const refreshed = await refreshSession();
        if (refreshed) {
          // Refresh succeeded — new access cookie set by server. Retry failed queries.
          queryClient.invalidateQueries();
          return;
        }
      } catch {
        // Refresh failed — fall through to logout
      } finally {
        isRefreshingSession = false;
      }
    }

    clearAllTokens();
    window.location.href = '/auth/login';
    return;
  }

  if (isEmailNotVerified) {
    window.dispatchEvent(new CustomEvent('email-not-verified'));
    return;
  }
};

queryClient.getQueryCache().subscribe(event => {
  if (event.type === "updated" && event.action.type === "error") {
    const error = event.query.state.error;
    redirectToLoginIfUnauthorized(error);
    console.error("[API Query Error]", error);
  }
});

queryClient.getMutationCache().subscribe(event => {
  if (event.type === "updated" && event.action.type === "error") {
    const error = event.mutation.state.error;
    redirectToLoginIfUnauthorized(error);
    console.error("[API Mutation Error]", error);
  }
});

const trpcClient = trpc.createClient({
  links: [
    httpBatchLink({
      url: "/api/trpc",
      transformer: superjson,
      async headers() {
        const csrfToken = await getCSRFToken();
        return {
          [CSRF_HEADER_NAME]: csrfToken,
          // Auth is handled by HttpOnly cookies (credentials: 'include')
        };
      },
      fetch(input, init) {
        return globalThis.fetch(input, {
          ...(init ?? {}),
          credentials: "include",
        });
      },
    }),
  ],
});

createRoot(document.getElementById("root")!).render(
  <trpc.Provider client={trpcClient} queryClient={queryClient}>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </trpc.Provider>
);
