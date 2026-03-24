/**
 * FileUploader Component Tests
 *
 * Tests the main FileUploader orchestrator component that composes
 * EncryptionPanel, EncryptionIndicator, DropZone, and UploadProgress.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FileUploader } from './index';
import { trpc } from '@/lib/trpc';
import * as useFileUploadModule from './hooks/useFileUpload';

// Mock tRPC
vi.mock('@/lib/trpc', () => ({
  trpc: {
    files: {
      getStorageStats: {
        useQuery: vi.fn(),
      },
    },
  },
}));

// Mock sub-components to isolate testing
vi.mock('./components/EncryptionPanel', () => ({
  EncryptionPanel: vi.fn(() => (
    <div data-testid="encryption-panel">
      Automatic Encryption Active
    </div>
  )),
}));

// EncryptionIndicator was removed — encryption status is handled within EncryptionPanel

vi.mock('./components/DropZone', () => ({
  DropZone: vi.fn(({ isDragging, maxSizeMB, onClick }) => (
    <div
      data-testid="drop-zone"
      data-dragging={isDragging}
      onClick={onClick}
    >
      Drop files here (max {maxSizeMB}MB)
    </div>
  )),
}));

vi.mock('./components/UploadProgress', () => ({
  UploadProgress: vi.fn(({ files, onRemove }) => (
    files.length > 0 ? (
      <div data-testid="upload-progress">
        {files.map((file: any) => (
          <div key={file.id} data-testid={`file-${file.id}`}>
            {file.file.name} - {file.status}
            <button onClick={() => onRemove(file.id)}>Remove</button>
          </div>
        ))}
      </div>
    ) : null
  )),
}));

// Mock useSignatureKeys (used for "sign by default" auto-enable)
vi.mock('@/hooks/useSignatureKeys', () => ({
  useSignatureKeys: vi.fn(() => ({
    keyInfo: { hasKeyPair: false, publicKey: null, fingerprint: null, keyVersion: null, userId: null },
    isLoading: false,
    isAvailable: null,
    generateKeyPair: vi.fn(),
    getSecretKey: vi.fn(),
    isPending: false,
    refetch: vi.fn(),
    keyHistory: undefined,
    isLoadingHistory: false,
  })),
}));

// Mock getSignByDefault
vi.mock('@/components/settings/SignatureKeysSection', () => ({
  getSignByDefault: vi.fn(() => false),
}));

// Mock SigningPanel (Phase 3.4 Sovereign)
vi.mock('./components/SigningPanel', () => ({
  SigningPanel: vi.fn(({ signingState }) => (
    signingState.enabled ? (
      <div data-testid="signing-panel">
        Signing: {signingState.keysReady ? 'Ready' : 'Not Ready'}
      </div>
    ) : (
      <div data-testid="signing-panel">Signing disabled</div>
    )
  )),
}));

// Mock useFolderUpload hook
vi.mock('./hooks/useFolderUpload', () => ({
  useFolderUpload: vi.fn(() => ({
    processFolderFiles: vi.fn(),
    processDroppedFolder: vi.fn(),
    isFolderUploading: false,
    folderUploadPhase: 'idle',
    folderInputRef: { current: null },
    FolderConflictDialogPortal: vi.fn(() => null),
  })),
}));

describe('FileUploader', () => {
  // Default mock for useFileUpload hook
  const mockUseFileUpload = {
    uploadFiles: [],
    isDragging: false,
    encryptionState: {
      isEncrypting: false,
      encryptingCount: 0,
      totalCount: 0,
      progress: 0,
    },
    isMultipartUpload: false,
    handleFiles: vi.fn(),
    handleFilesToFolder: vi.fn(),
    removeFile: vi.fn(),
    retryFile: vi.fn(),
    handleDragOver: vi.fn(),
    handleDragLeave: vi.fn(),
    handleDrop: vi.fn(),
    fileInputRef: { current: null },
  };

  beforeEach(() => {
    vi.clearAllMocks();

    // Mock tRPC storage stats query
    vi.mocked(trpc.files.getStorageStats.useQuery).mockReturnValue({
      data: {
        maxFileSize: 100 * 1024 * 1024, // 100MB
        usedSpace: 0,
        totalSpace: 1024 * 1024 * 1024,
      },
    } as any);

    // Mock useFileUpload hook
    vi.spyOn(useFileUploadModule, 'useFileUpload').mockReturnValue(mockUseFileUpload);
  });

  describe('Component Rendering', () => {
    it('should render all sub-components', () => {
      render(<FileUploader folderId={1} />);

      expect(screen.getByTestId('encryption-panel')).toBeInTheDocument();
      expect(screen.getByTestId('drop-zone')).toBeInTheDocument();
      expect(screen.getByTestId('signing-panel')).toBeInTheDocument();
    });

    it('should show automatic encryption message', () => {
      render(<FileUploader folderId={1} />);

      expect(screen.getByText(/automatic encryption active/i)).toBeInTheDocument();
    });

    it('should apply custom className', () => {
      const { container } = render(
        <FileUploader folderId={1} className="custom-class" />
      );

      const wrapper = container.firstChild as HTMLElement;
      expect(wrapper).toHaveClass('custom-class');
    });
  });

  describe('Max File Size Configuration', () => {
    it('should use prop maxSize if provided', () => {
      const customMaxSize = 50 * 1024 * 1024; // 50MB
      render(<FileUploader folderId={1} maxSize={customMaxSize} />);

      expect(screen.getByText(/max 50MB/i)).toBeInTheDocument();
    });

    it('should use server maxFileSize if no prop provided', () => {
      render(<FileUploader folderId={1} />);

      // Server returns 100MB in the mock
      expect(screen.getByText(/max 100MB/i)).toBeInTheDocument();
    });

    it('should use default 100MB if no prop and no server data', () => {
      vi.mocked(trpc.files.getStorageStats.useQuery).mockReturnValue({
        data: undefined,
      } as any);

      render(<FileUploader folderId={1} />);

      expect(screen.getByText(/max 100MB/i)).toBeInTheDocument();
    });
  });

  describe('Encryption State Integration', () => {
    it('should always show encryption panel regardless of upload state', () => {
      render(<FileUploader folderId={1} />);

      expect(screen.getByTestId('encryption-panel')).toBeInTheDocument();
    });
  });

  describe('Upload Files Display', () => {
    it('should display upload progress when files are present', () => {
      const mockFile = new File(['content'], 'test.txt', { type: 'text/plain' });
      const uploadFiles = [
        {
          id: '1',
          file: mockFile,
          progress: 0,
          status: 'pending' as const,
        },
      ];

      vi.spyOn(useFileUploadModule, 'useFileUpload').mockReturnValue({
        ...mockUseFileUpload,
        uploadFiles,
      });

      render(<FileUploader folderId={1} />);

      expect(screen.getByTestId('upload-progress')).toBeInTheDocument();
      expect(screen.getByText(/test.txt - pending/i)).toBeInTheDocument();
    });

    it('should call removeFile when remove button is clicked', async () => {
      const user = userEvent.setup();
      const mockFile = new File(['content'], 'test.txt', { type: 'text/plain' });
      const uploadFiles = [
        {
          id: 'file-1',
          file: mockFile,
          progress: 50,
          status: 'uploading' as const,
        },
      ];

      vi.spyOn(useFileUploadModule, 'useFileUpload').mockReturnValue({
        ...mockUseFileUpload,
        uploadFiles,
      });

      render(<FileUploader folderId={1} />);

      const removeButton = screen.getByRole('button', { name: /remove/i });
      await user.click(removeButton);

      expect(mockUseFileUpload.removeFile).toHaveBeenCalledWith('file-1');
    });
  });

  describe('Drag and Drop State', () => {
    it('should pass dragging state to DropZone', () => {
      vi.spyOn(useFileUploadModule, 'useFileUpload').mockReturnValue({
        ...mockUseFileUpload,
        isDragging: true,
      });

      render(<FileUploader folderId={1} />);

      const dropZone = screen.getByTestId('drop-zone');
      expect(dropZone).toHaveAttribute('data-dragging', 'true');
    });
  });

  describe('Hook Configuration', () => {
    it('should pass correct params to useFileUpload hook', () => {
      const onUploadComplete = vi.fn();
      const customMaxSize = 200 * 1024 * 1024;

      render(
        <FileUploader
          folderId={42}
          onUploadComplete={onUploadComplete}
          maxFiles={5}
          maxSize={customMaxSize}
        />
      );

      expect(useFileUploadModule.useFileUpload).toHaveBeenCalledWith(
        expect.objectContaining({
          folderId: 42,
          maxFiles: 5,
          maxSize: customMaxSize,
          onUploadComplete,
          signingContext: null, // Phase 3.4 Sovereign
          showDuplicateDialog: expect.any(Function),
        })
      );
    });

    it('should use default maxFiles if not provided', () => {
      render(<FileUploader folderId={1} />);

      expect(useFileUploadModule.useFileUpload).toHaveBeenCalledWith(
        expect.objectContaining({
          maxFiles: 10,
        })
      );
    });

    it('should pass null folderId for root uploads', () => {
      render(<FileUploader folderId={null} />);

      expect(useFileUploadModule.useFileUpload).toHaveBeenCalledWith(
        expect.objectContaining({
          folderId: null,
        })
      );
    });
  });

  describe('Multiple Files Upload', () => {
    it('should display multiple files in upload progress', () => {
      const files = [
        {
          id: '1',
          file: new File(['a'], 'file1.txt', { type: 'text/plain' }),
          progress: 30,
          status: 'uploading' as const,
        },
        {
          id: '2',
          file: new File(['b'], 'file2.txt', { type: 'text/plain' }),
          progress: 0,
          status: 'pending' as const,
        },
        {
          id: '3',
          file: new File(['c'], 'file3.txt', { type: 'text/plain' }),
          progress: 100,
          status: 'completed' as const,
        },
      ];

      vi.spyOn(useFileUploadModule, 'useFileUpload').mockReturnValue({
        ...mockUseFileUpload,
        uploadFiles: files,
      });

      render(<FileUploader folderId={1} />);

      expect(screen.getByText(/file1.txt - uploading/i)).toBeInTheDocument();
      expect(screen.getByText(/file2.txt - pending/i)).toBeInTheDocument();
      expect(screen.getByText(/file3.txt - completed/i)).toBeInTheDocument();
    });
  });

  describe('Integration', () => {
    it('should integrate all components correctly', () => {
      const mockFile = new File(['test'], 'document.pdf', { type: 'application/pdf' });
      const uploadFiles = [
        {
          id: 'upload-1',
          file: mockFile,
          progress: 75,
          status: 'uploading' as const,
        },
      ];

      vi.spyOn(useFileUploadModule, 'useFileUpload').mockReturnValue({
        ...mockUseFileUpload,
        uploadFiles,
        encryptionState: {
          isEncrypting: false,
          encryptingCount: 0,
          totalCount: 0,
          progress: 0,
        },
        isDragging: false,
      });

      render(<FileUploader folderId={1} />);

      // All components should be present
      expect(screen.getByTestId('encryption-panel')).toBeInTheDocument();
      expect(screen.getByTestId('drop-zone')).toBeInTheDocument();
      expect(screen.getByTestId('upload-progress')).toBeInTheDocument();

      // Upload progress should show the file
      expect(screen.getByText(/document.pdf - uploading/i)).toBeInTheDocument();
    });
  });
});
