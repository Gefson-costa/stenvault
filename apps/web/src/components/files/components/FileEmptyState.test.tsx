/**
 * FileEmptyState Component Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FileEmptyState } from './FileEmptyState';

// Mock framer-motion to avoid animation issues in tests
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
}));

// Mock Button component
vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}));

describe('FileEmptyState', () => {
  it('should render empty state message', () => {
    render(<FileEmptyState />);

    expect(screen.getByText(/no files yet/i)).toBeInTheDocument();
  });

  it('should render description text', () => {
    render(<FileEmptyState />);

    expect(screen.getByText(/drop files here or click upload to get started/i)).toBeInTheDocument();
  });

  it('should render upload button', () => {
    render(<FileEmptyState />);

    expect(screen.getByRole('button', { name: /upload/i })).toBeInTheDocument();
  });

  it('should call onUploadRequest when button clicked', async () => {
    const onUploadRequest = vi.fn();
    render(<FileEmptyState onUploadRequest={onUploadRequest} />);

    const button = screen.getByRole('button', { name: /upload/i });
    await userEvent.click(button);

    expect(onUploadRequest).toHaveBeenCalledTimes(1);
  });

  it('should render without onUploadRequest prop', () => {
    render(<FileEmptyState />);

    // Should render without errors
    expect(screen.getByRole('button', { name: /upload/i })).toBeInTheDocument();
  });

  it('should have sparkles icon', () => {
    const { container } = render(<FileEmptyState />);

    // Sparkles icon should be present
    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
  });
});
