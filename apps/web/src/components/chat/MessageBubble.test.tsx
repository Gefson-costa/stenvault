/**
 * MessageBubble Component Tests
 *
 * Tests chat message bubble including hybrid PQC encryption/decryption,
 * read receipts, timestamps, and file attachments.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MessageBubble } from './MessageBubble';

// Hoisted mocks (declared before vi.mock is executed)
const { mockDecryptMessage, mockGetUnlockedHybridSecretKey, mockFetch, mockGetShareDetailsQuery } = vi.hoisted(() => ({
  mockDecryptMessage: vi.fn(),
  mockGetUnlockedHybridSecretKey: vi.fn(),
  mockFetch: vi.fn(),
  mockGetShareDetailsQuery: vi.fn(),
}));

// Mock date-fns
vi.mock('date-fns', () => ({
  format: vi.fn((date: Date, formatStr: string) => {
    if (formatStr === 'HH:mm') return '14:30';
    return date.toISOString();
  }),
}));

// Mock sonner
vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

// Mock useE2ECrypto
vi.mock('@/hooks/useE2ECrypto', () => ({
  useE2ECrypto: () => ({
    decryptMessage: mockDecryptMessage,
  }),
}));

// Mock useMasterKey
vi.mock('@/hooks/useMasterKey', () => ({
  useMasterKey: () => ({
    getUnlockedHybridSecretKey: mockGetUnlockedHybridSecretKey,
  }),
}));

// Mock tRPC
vi.mock('@/lib/trpc', () => ({
  trpc: {
    useUtils: () => ({
      chat: {
        getAttachmentDownloadUrl: {
          fetch: mockFetch,
        },
      },
    }),
    chatFileShare: {
      getShareDetails: {
        useQuery: mockGetShareDetailsQuery,
      },
    },
  },
}));

// Mock UI components
vi.mock('@/components/ui/avatar', () => ({
  Avatar: ({ children, className }: any) => (
    <div data-testid="avatar" className={className}>
      {children}
    </div>
  ),
  AvatarFallback: ({ children, className }: any) => (
    <div data-testid="avatar-fallback" className={className}>
      {children}
    </div>
  ),
}));

// Mock AttachmentPreview
vi.mock('./shared', () => ({
  AttachmentPreview: ({ fileName, fileSize, fileType, onDownload, isOwn }: any) => (
    <div data-testid="attachment-preview">
      <span data-testid="file-name">{fileName}</span>
      <span data-testid="file-size">{fileSize}</span>
      <span data-testid="file-type">{fileType}</span>
      <button onClick={onDownload} data-testid="download-button">
        Download
      </button>
      <span data-testid="is-own">{isOwn ? 'own' : 'other'}</span>
    </div>
  ),
}));

// Mock SharedFileCard (has many lucide-react dependencies)
vi.mock('./SharedFileCard', () => ({
  SharedFileCard: ({ file, isOwn }: any) => (
    <div data-testid="shared-file-card">
      <span data-testid="shared-filename">{file?.filename}</span>
      <span data-testid="shared-is-own">{isOwn ? 'own' : 'other'}</span>
    </div>
  ),
}));

// Mock lucide icons
vi.mock('lucide-react', () => ({
  Check: () => <div data-testid="icon-check" />,
  CheckCheck: () => <div data-testid="icon-check-check" />,
  Lock: () => <div data-testid="icon-lock" />,
}));

const mockHybridSecretKey = { classical: new Uint8Array(32), postQuantum: new Uint8Array(2400) };

const baseMessage = {
  id: 1,
  createdAt: new Date('2026-01-24T14:30:00'),
  fromUserId: 2,
  content: 'Hello World',
  messageType: 'text' as const,
  isEncrypted: false,
  isRead: false,
  iv: null,
  salt: null,
  kemCiphertext: null,
  fileKey: null,
  filename: null,
  fileSize: null,
};

describe('MessageBubble', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockDecryptMessage.mockResolvedValue('Decrypted message');
    mockGetUnlockedHybridSecretKey.mockResolvedValue(mockHybridSecretKey);
    mockFetch.mockResolvedValue({ url: 'https://example.com/file.pdf' });
    mockGetShareDetailsQuery.mockReturnValue({ data: undefined, isLoading: false });
  });

  describe('Message Rendering', () => {
    it('should render text message', () => {
      render(<MessageBubble message={baseMessage} isOwn={false} />);

      expect(screen.getByText('Hello World')).toBeInTheDocument();
    });

    it('should render own message with different styling', () => {
      const { container } = render(
        <MessageBubble message={baseMessage} isOwn={true} />
      );

      const messageContainer = container.querySelector('[class*="flex-row-reverse"]');
      expect(messageContainer).toBeInTheDocument();
    });

    it('should render received message with avatar', () => {
      render(<MessageBubble message={baseMessage} isOwn={false} />);

      expect(screen.getByTestId('avatar')).toBeInTheDocument();
      expect(screen.getByTestId('avatar-fallback')).toBeInTheDocument();
    });

    it('should not render avatar for own messages', () => {
      render(<MessageBubble message={baseMessage} isOwn={true} />);

      expect(screen.queryByTestId('avatar')).not.toBeInTheDocument();
    });

    it('should hide avatar when showAvatar is false', () => {
      render(
        <MessageBubble message={baseMessage} isOwn={false} showAvatar={false} />
      );

      expect(screen.queryByTestId('avatar-fallback')).not.toBeInTheDocument();
    });

    it('should render timestamp', () => {
      render(<MessageBubble message={baseMessage} isOwn={false} />);

      expect(screen.getByText('14:30')).toBeInTheDocument();
    });
  });

  describe('Read Receipts', () => {
    it('should show single check for unread own message', () => {
      const unreadMessage = { ...baseMessage, isRead: false };
      render(<MessageBubble message={unreadMessage} isOwn={true} />);

      expect(screen.getByTestId('icon-check')).toBeInTheDocument();
      expect(screen.queryByTestId('icon-check-check')).not.toBeInTheDocument();
    });

    it('should show double check for read own message', () => {
      const readMessage = { ...baseMessage, isRead: true };
      render(<MessageBubble message={readMessage} isOwn={true} />);

      expect(screen.getByTestId('icon-check-check')).toBeInTheDocument();
      expect(screen.queryByTestId('icon-check')).not.toBeInTheDocument();
    });

    it('should not show read receipts for received messages', () => {
      render(<MessageBubble message={baseMessage} isOwn={false} />);

      expect(screen.queryByTestId('icon-check')).not.toBeInTheDocument();
      expect(screen.queryByTestId('icon-check-check')).not.toBeInTheDocument();
    });
  });

  describe('Encrypted Messages', () => {
    it('should show encryption indicator', () => {
      const encryptedMessage = {
        ...baseMessage,
        isEncrypted: true,
        content: 'encrypted-content',
        iv: 'test-iv',
        salt: 'test-salt',
        kemCiphertext: '{"classical":"abc","postQuantum":"xyz"}',
      };
      render(<MessageBubble message={encryptedMessage} isOwn={false} />);

      expect(screen.getByTestId('icon-lock')).toBeInTheDocument();
    });

    it('should decrypt encrypted message using hybrid KEM', async () => {
      const encryptedMessage = {
        ...baseMessage,
        isEncrypted: true,
        content: 'encrypted-content',
        iv: 'test-iv',
        salt: 'test-salt',
        kemCiphertext: '{"classical":"abc","postQuantum":"xyz"}',
      };
      mockDecryptMessage.mockResolvedValue('Decrypted content');

      render(<MessageBubble message={encryptedMessage} isOwn={false} />);

      await waitFor(() => {
        expect(mockGetUnlockedHybridSecretKey).toHaveBeenCalled();
        expect(mockDecryptMessage).toHaveBeenCalledWith(
          'encrypted-content',
          'test-iv',
          'test-salt',
          '{"classical":"abc","postQuantum":"xyz"}',
          mockHybridSecretKey
        );
      });

      await waitFor(() => {
        expect(screen.getByText('Decrypted content')).toBeInTheDocument();
      });
    });

    it('should show decrypting state', () => {
      const encryptedMessage = {
        ...baseMessage,
        isEncrypted: true,
        content: 'encrypted-content',
        iv: 'test-iv',
        salt: 'test-salt',
        kemCiphertext: '{"classical":"abc","postQuantum":"xyz"}',
      };
      mockDecryptMessage.mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve('Done'), 100))
      );

      render(<MessageBubble message={encryptedMessage} isOwn={false} />);

      expect(screen.getByText(/decrypting/i)).toBeInTheDocument();
    });

    it('should handle decryption error', async () => {
      const encryptedMessage = {
        ...baseMessage,
        isEncrypted: true,
        content: 'encrypted-content',
        iv: 'test-iv',
        salt: 'test-salt',
        kemCiphertext: '{"classical":"abc","postQuantum":"xyz"}',
      };
      mockDecryptMessage.mockRejectedValue(new Error('Decryption failed'));

      render(<MessageBubble message={encryptedMessage} isOwn={false} />);

      await waitFor(() => {
        expect(screen.getByText(/decryption error/i)).toBeInTheDocument();
      });
    });

    it('should show error when hybrid secret key not available', async () => {
      const encryptedMessage = {
        ...baseMessage,
        isEncrypted: true,
        content: 'encrypted-content',
        iv: 'test-iv',
        salt: 'test-salt',
        kemCiphertext: '{"classical":"abc","postQuantum":"xyz"}',
      };
      mockGetUnlockedHybridSecretKey.mockResolvedValue(null);

      render(<MessageBubble message={encryptedMessage} isOwn={false} />);

      await waitFor(() => {
        expect(screen.getByText(/vault locked/i)).toBeInTheDocument();
      });
    });
  });

  describe('File Attachments', () => {
    it('should render image attachment', () => {
      const imageMessage = {
        ...baseMessage,
        messageType: 'image' as const,
        content: null,
        filename: 'photo.jpg',
        fileSize: 1024000,
        fileKey: 'image-key-123',
      };

      render(<MessageBubble message={imageMessage} isOwn={false} />);

      expect(screen.getByTestId('attachment-preview')).toBeInTheDocument();
      expect(screen.getByTestId('file-name')).toHaveTextContent('photo.jpg');
      expect(screen.getByTestId('file-type')).toHaveTextContent('image');
    });

    it('should render video attachment', () => {
      const videoMessage = {
        ...baseMessage,
        messageType: 'video' as const,
        content: null,
        filename: 'video.mp4',
        fileSize: 5000000,
        fileKey: 'video-key-456',
      };

      render(<MessageBubble message={videoMessage} isOwn={false} />);

      expect(screen.getByTestId('file-type')).toHaveTextContent('video');
    });

    it('should render file attachment', () => {
      const fileMessage = {
        ...baseMessage,
        messageType: 'file' as const,
        content: null,
        filename: 'document.pdf',
        fileSize: 2048000,
        fileKey: 'file-key-789',
      };

      render(<MessageBubble message={fileMessage} isOwn={false} />);

      expect(screen.getByTestId('file-type')).toHaveTextContent('other');
    });

    it('should call download handler', async () => {
      const user = userEvent.setup();
      const fileMessage = {
        ...baseMessage,
        messageType: 'file' as const,
        content: null,
        filename: 'document.pdf',
        fileSize: 2048000,
        fileKey: 'file-key-789',
      };

      render(<MessageBubble message={fileMessage} isOwn={false} />);

      const downloadButton = screen.getByTestId('download-button');
      await user.click(downloadButton);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith({ fileKey: 'file-key-789' });
      });
    });
  });

  describe('Empty States', () => {
    it('should show placeholder for empty text message', () => {
      const emptyMessage = { ...baseMessage, content: null };
      render(<MessageBubble message={emptyMessage} isOwn={false} />);

      expect(screen.getByText(/empty message/i)).toBeInTheDocument();
    });

    it('should show placeholder for empty content', () => {
      const emptyMessage = { ...baseMessage, content: '' };
      render(<MessageBubble message={emptyMessage} isOwn={false} />);

      expect(screen.getByText(/empty message/i)).toBeInTheDocument();
    });
  });

  describe('Message Styling', () => {
    it('should apply own message styling', () => {
      const { container } = render(
        <MessageBubble message={baseMessage} isOwn={true} />
      );

      const bubble = container.querySelector('[class*="bg-primary"]');
      expect(bubble).toBeInTheDocument();
    });

    it('should apply received message styling', () => {
      const { container } = render(
        <MessageBubble message={baseMessage} isOwn={false} />
      );

      const bubble = container.querySelector('[class*="bg-muted"]');
      expect(bubble).toBeInTheDocument();
    });
  });

  describe('Integration', () => {
    it('should render complete own message with all elements', () => {
      const ownMessage = { ...baseMessage, isRead: true };
      render(<MessageBubble message={ownMessage} isOwn={true} />);

      // Content
      expect(screen.getByText('Hello World')).toBeInTheDocument();

      // Timestamp
      expect(screen.getByText('14:30')).toBeInTheDocument();

      // Read receipt
      expect(screen.getByTestId('icon-check-check')).toBeInTheDocument();

      // No avatar
      expect(screen.queryByTestId('avatar')).not.toBeInTheDocument();
    });

    it('should render complete received encrypted message', async () => {
      const encryptedMessage = {
        ...baseMessage,
        isEncrypted: true,
        content: 'encrypted-content',
        iv: 'test-iv',
        salt: 'test-salt',
        kemCiphertext: '{"classical":"abc","postQuantum":"xyz"}',
      };
      mockDecryptMessage.mockResolvedValue('Decrypted message');

      render(<MessageBubble message={encryptedMessage} isOwn={false} />);

      // Avatar
      expect(screen.getByTestId('avatar')).toBeInTheDocument();

      // Lock icon
      expect(screen.getByTestId('icon-lock')).toBeInTheDocument();

      // Decrypted content
      await waitFor(() => {
        expect(screen.getByText('Decrypted message')).toBeInTheDocument();
      });

      // Timestamp
      expect(screen.getByText('14:30')).toBeInTheDocument();
    });
  });
});
