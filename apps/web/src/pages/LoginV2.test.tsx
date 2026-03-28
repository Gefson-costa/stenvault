/**
 * LoginV2 Component Tests
 *
 * Tests the login page including OPAQUE password login, magic link,
 * OTP verification, and auth method toggling.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LoginV2 from './LoginV2';

// Mock react-router-dom
const mockSetLocation = vi.fn();
vi.mock('react-router-dom', () => ({
  useLocation: vi.fn(() => ({ pathname: '' })),
  useNavigate: vi.fn(() => mockSetLocation),
}));

// Mock sonner
vi.mock('sonner');

// Mock auth (storeTokenPair is no-op after HttpOnly cookie migration)
vi.mock('@/lib/auth', () => ({
  storeTokenPair: vi.fn(),
  clearAllTokens: vi.fn(),
  scheduleProactiveRefresh: vi.fn(),
}));

// Mock OPAQUE client
const mockOpaqueStartLogin = vi.fn();
const mockOpaqueFinishLogin = vi.fn();
vi.mock('@/lib/opaqueClient', () => ({
  startLogin: (...args: any[]) => mockOpaqueStartLogin(...args),
  finishLogin: (...args: any[]) => mockOpaqueFinishLogin(...args),
}));

// Mock tRPC
const mockOpaqueLoginStartMutation = {
  mutateAsync: vi.fn(),
  isPending: false,
};

const mockOpaqueLoginFinishMutation = {
  mutateAsync: vi.fn(),
  isPending: false,
};

const mockSendMagicLinkMutation = {
  mutateAsync: vi.fn(),
  isPending: false,
};

const mockVerifyOtpMutation = {
  mutateAsync: vi.fn(),
  isPending: false,
};

const mockVerifyMFAMutation = {
  mutateAsync: vi.fn(),
  isPending: false,
};

const mockInvalidate = vi.fn();

vi.mock('@/lib/trpc', () => ({
  trpc: {
    useUtils: vi.fn(() => ({
      auth: {
        me: {
          invalidate: mockInvalidate,
        },
      },
    })),
    auth: {
      opaqueLoginStart: {
        useMutation: vi.fn(() => mockOpaqueLoginStartMutation),
      },
      opaqueLoginFinish: {
        useMutation: vi.fn(() => mockOpaqueLoginFinishMutation),
      },
      sendMagicLink: {
        useMutation: vi.fn(() => mockSendMagicLinkMutation),
      },
      verifyOTP: {
        useMutation: vi.fn(() => mockVerifyOtpMutation),
      },
      verifyMFA: {
        useMutation: vi.fn(() => mockVerifyMFAMutation),
      },
      me: {
        useQuery: vi.fn(() => ({
          data: null,
          refetch: vi.fn(),
        })),
      },
    },
    passkeys: {
      generateAuthOptions: {
        useMutation: vi.fn(() => ({ mutateAsync: vi.fn(), isPending: false })),
      },
      verifyAuthentication: {
        useMutation: vi.fn(() => ({ mutateAsync: vi.fn(), isPending: false })),
      },
    },
  },
}));

// Mock @simplewebauthn/browser
vi.mock('@simplewebauthn/browser', () => ({
  browserSupportsWebAuthn: vi.fn(() => true),
  startAuthentication: vi.fn(),
}));

// Mock auth components
vi.mock('@/components/auth', () => ({
  AuthLayout: ({ children }: any) => <div data-testid="auth-layout">{children}</div>,
  AuthCard: ({ title, description, children }: any) => (
    <div data-testid="auth-card">
      <h1>{title}</h1>
      <p>{description}</p>
      {children}
    </div>
  ),
  AuthInput: ({ id, label, value, onChange, type, placeholder, required }: any) => (
    <div>
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        type={type || 'text'}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        required={required}
      />
    </div>
  ),
  AuthButton: ({ children, onClick, type, isLoading, disabled }: any) => (
    <button type={type} onClick={onClick} disabled={isLoading || disabled}>
      {isLoading ? 'Loading...' : children}
    </button>
  ),
  AuthDivider: ({ text }: any) => <div data-testid="divider">{text}</div>,
  AuthLink: ({ href, children }: any) => <a href={href}>{children}</a>,
}));

describe('LoginV2', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSetLocation.mockClear();
    mockInvalidate.mockClear();

    // Reset mutation mocks
    Object.assign(mockOpaqueLoginStartMutation, {
      mutateAsync: vi.fn(),
      isPending: false,
    });

    Object.assign(mockOpaqueLoginFinishMutation, {
      mutateAsync: vi.fn(),
      isPending: false,
    });

    Object.assign(mockSendMagicLinkMutation, {
      mutateAsync: vi.fn(),
      isPending: false,
    });

    Object.assign(mockVerifyOtpMutation, {
      mutateAsync: vi.fn(),
      isPending: false,
    });

    Object.assign(mockVerifyMFAMutation, {
      mutateAsync: vi.fn(),
      isPending: false,
    });

    // Default OPAQUE mock behavior
    mockOpaqueStartLogin.mockResolvedValue({
      clientLoginState: 'mock-client-state',
      startLoginRequest: 'mock-start-request',
    });

    mockOpaqueFinishLogin.mockResolvedValue({
      finishLoginRequest: 'mock-finish-request',
      sessionKey: 'mock-session-key',
      exportKey: 'mock-export-key',
      serverStaticPublicKey: 'mock-pk',
    });
  });

  describe('Password Login View', () => {
    it('should render password login form by default', () => {
      render(<LoginV2 />);

      expect(screen.getByText('Sign in')).toBeInTheDocument();
      expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /continue/i })).toBeInTheDocument();
    });

    it('should render forgot password link', () => {
      render(<LoginV2 />);

      expect(screen.getByText(/lost your password/i)).toBeInTheDocument();
    });

    it('should render register link', () => {
      render(<LoginV2 />);

      expect(screen.getByText(/create one for free/i)).toBeInTheDocument();
    });

    it('should allow typing email and password', async () => {
      const user = userEvent.setup();
      render(<LoginV2 />);

      const emailInput = screen.getByLabelText(/email address/i);
      const passwordInput = screen.getByLabelText(/password/i);

      await user.type(emailInput, 'test@example.com');
      await user.type(passwordInput, 'password123');

      expect(emailInput).toHaveValue('test@example.com');
      expect(passwordInput).toHaveValue('password123');
    });

    it('should submit OPAQUE password login', async () => {
      const user = userEvent.setup();

      mockOpaqueLoginStartMutation.mutateAsync.mockResolvedValue({
        loginResponse: 'mock-login-response',
      });

      mockOpaqueLoginFinishMutation.mutateAsync.mockResolvedValue({
        accessToken: 'test-token',
        credentials: {
          accessToken: 'test-token',
          refreshToken: 'refresh-token',
          expiresIn: 3600,
        },
      });

      render(<LoginV2 />);

      await user.type(screen.getByLabelText(/email address/i), 'test@example.com');
      await user.type(screen.getByLabelText(/password/i), 'password123');
      await user.click(screen.getByRole('button', { name: /continue/i }));

      // Verify OPAQUE client was called
      await waitFor(() => {
        expect(mockOpaqueStartLogin).toHaveBeenCalledWith('password123');
      });

      // Verify server calls
      await waitFor(() => {
        expect(mockOpaqueLoginStartMutation.mutateAsync).toHaveBeenCalledWith({
          email: 'test@example.com',
          startLoginRequest: 'mock-start-request',
        });
      });

      await waitFor(() => {
        expect(mockSetLocation).toHaveBeenCalledWith('/home');
      });
    });
  });

  describe('Magic Link View', () => {
    it('should switch to magic link mode', async () => {
      const user = userEvent.setup();
      render(<LoginV2 />);

      await user.click(screen.getByRole('button', { name: /use magic link/i }));

      expect(screen.getByText('Magic Link')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /send code/i })).toBeInTheDocument();
      expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument();
    });

    it('should send magic link', async () => {
      const user = userEvent.setup();
      mockSendMagicLinkMutation.mutateAsync.mockResolvedValue({ success: true });

      render(<LoginV2 />);

      // Switch to magic link mode
      await user.click(screen.getByRole('button', { name: /use magic link/i }));

      // Enter email
      await user.type(screen.getByLabelText(/email address/i), 'test@example.com');
      await user.click(screen.getByRole('button', { name: /send code/i }));

      expect(mockSendMagicLinkMutation.mutateAsync).toHaveBeenCalledWith({
        email: 'test@example.com',
      });
    });

    it('should switch back to password mode', async () => {
      const user = userEvent.setup();
      render(<LoginV2 />);

      await user.click(screen.getByRole('button', { name: /use magic link/i }));
      expect(screen.getByText('Magic Link')).toBeInTheDocument();

      await user.click(screen.getByRole('button', { name: /use password/i }));
      expect(screen.getByText('Sign in')).toBeInTheDocument();
      expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    });
  });

  describe('OTP Verification View', () => {
    it('should show OTP input after sending magic link', async () => {
      const user = userEvent.setup();
      mockSendMagicLinkMutation.mutateAsync.mockResolvedValue({ success: true });

      render(<LoginV2 />);

      await user.click(screen.getByRole('button', { name: /use magic link/i }));
      await user.type(screen.getByLabelText(/email address/i), 'test@example.com');
      await user.click(screen.getByRole('button', { name: /send code/i }));

      await waitFor(() => {
        expect(screen.getByText('Enter Code')).toBeInTheDocument();
        expect(screen.getByPlaceholderText('000000')).toBeInTheDocument();
      });
    });

    it('should allow entering 6-digit OTP', async () => {
      const user = userEvent.setup();
      mockSendMagicLinkMutation.mutateAsync.mockResolvedValue({ success: true });

      render(<LoginV2 />);

      await user.click(screen.getByRole('button', { name: /use magic link/i }));
      await user.type(screen.getByLabelText(/email address/i), 'test@example.com');
      await user.click(screen.getByRole('button', { name: /send code/i }));

      await waitFor(() => {
        expect(screen.getByPlaceholderText('000000')).toBeInTheDocument();
      });

      const otpInput = screen.getByPlaceholderText('000000');
      await user.type(otpInput, '123456');

      expect(otpInput).toHaveValue('123456');
    });

    it('should verify OTP and login', async () => {
      const user = userEvent.setup();
      mockSendMagicLinkMutation.mutateAsync.mockResolvedValue({ success: true });
      mockVerifyOtpMutation.mutateAsync.mockResolvedValue({
        accessToken: 'test-token',
        credentials: {
          accessToken: 'test-token',
          refreshToken: 'refresh-token',
          expiresIn: 3600,
        },
      });

      render(<LoginV2 />);

      await user.click(screen.getByRole('button', { name: /use magic link/i }));
      await user.type(screen.getByLabelText(/email address/i), 'test@example.com');
      await user.click(screen.getByRole('button', { name: /send code/i }));

      await waitFor(() => {
        expect(screen.getByPlaceholderText('000000')).toBeInTheDocument();
      });

      await user.type(screen.getByPlaceholderText('000000'), '123456');
      await user.click(screen.getByRole('button', { name: /verify & sign in/i }));

      expect(mockVerifyOtpMutation.mutateAsync).toHaveBeenCalledWith({
        email: 'test@example.com',
        otp: '123456',
      });

      await waitFor(() => {
        expect(mockSetLocation).toHaveBeenCalledWith('/home');
      });
    });

    it('should disable verify button until 6 digits entered', async () => {
      const user = userEvent.setup();
      mockSendMagicLinkMutation.mutateAsync.mockResolvedValue({ success: true });

      render(<LoginV2 />);

      await user.click(screen.getByRole('button', { name: /use magic link/i }));
      await user.type(screen.getByLabelText(/email address/i), 'test@example.com');
      await user.click(screen.getByRole('button', { name: /send code/i }));

      await waitFor(() => {
        expect(screen.getByPlaceholderText('000000')).toBeInTheDocument();
      });

      const verifyButton = screen.getByRole('button', { name: /verify & sign in/i });
      expect(verifyButton).toBeDisabled();

      await user.type(screen.getByPlaceholderText('000000'), '12345');
      expect(verifyButton).toBeDisabled();

      await user.type(screen.getByPlaceholderText('000000'), '6');
      expect(verifyButton).not.toBeDisabled();
    });

    it('should allow resending code', async () => {
      const user = userEvent.setup();
      mockSendMagicLinkMutation.mutateAsync.mockResolvedValue({ success: true });

      render(<LoginV2 />);

      await user.click(screen.getByRole('button', { name: /use magic link/i }));
      await user.type(screen.getByLabelText(/email address/i), 'test@example.com');
      await user.click(screen.getByRole('button', { name: /send code/i }));

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /resend code/i })).toBeInTheDocument();
      });

      mockSendMagicLinkMutation.mutateAsync.mockClear();
      await user.click(screen.getByRole('button', { name: /resend code/i }));

      expect(mockSendMagicLinkMutation.mutateAsync).toHaveBeenCalledWith({
        email: 'test@example.com',
      });
    });

    it('should allow going back to email input', async () => {
      const user = userEvent.setup();
      mockSendMagicLinkMutation.mutateAsync.mockResolvedValue({ success: true });

      render(<LoginV2 />);

      await user.click(screen.getByRole('button', { name: /use magic link/i }));
      await user.type(screen.getByLabelText(/email address/i), 'test@example.com');
      await user.click(screen.getByRole('button', { name: /send code/i }));

      await waitFor(() => {
        expect(screen.getByText(/use different email/i)).toBeInTheDocument();
      });

      await user.click(screen.getByText(/use different email/i));

      expect(screen.getByText('Magic Link')).toBeInTheDocument();
      expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
    });
  });

  describe('Integration', () => {
    it('should render complete login page', () => {
      render(<LoginV2 />);

      expect(screen.getByTestId('auth-layout')).toBeInTheDocument();
      expect(screen.getByTestId('auth-card')).toBeInTheDocument();
      expect(screen.getByText('Sign in')).toBeInTheDocument();
      expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    });

    it('should handle complete OPAQUE password login flow', async () => {
      const user = userEvent.setup();

      mockOpaqueLoginStartMutation.mutateAsync.mockResolvedValue({
        loginResponse: 'mock-login-response',
      });

      mockOpaqueLoginFinishMutation.mutateAsync.mockResolvedValue({
        accessToken: 'token',
        credentials: {
          accessToken: 'token',
          refreshToken: 'refresh',
          expiresIn: 3600,
        },
      });

      render(<LoginV2 />);

      await user.type(screen.getByLabelText(/email address/i), 'user@example.com');
      await user.type(screen.getByLabelText(/password/i), 'secure123');
      await user.click(screen.getByRole('button', { name: /continue/i }));

      // Verify 4-step OPAQUE flow
      await waitFor(() => {
        expect(mockOpaqueStartLogin).toHaveBeenCalledWith('secure123');
        expect(mockOpaqueLoginStartMutation.mutateAsync).toHaveBeenCalled();
        expect(mockOpaqueFinishLogin).toHaveBeenCalled();
        expect(mockOpaqueLoginFinishMutation.mutateAsync).toHaveBeenCalled();
      });

      await waitFor(() => {
        expect(mockSetLocation).toHaveBeenCalledWith('/home');
      });
    });
  });
});
