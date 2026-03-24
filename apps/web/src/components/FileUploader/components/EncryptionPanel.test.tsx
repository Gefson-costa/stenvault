/**
 * EncryptionPanel Component Tests
 *
 * Encryption is always mandatory via Master Key - panel shows status only.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { EncryptionPanel } from './EncryptionPanel';

describe('EncryptionPanel', () => {
  it('should render zero-knowledge encryption message', () => {
    render(<EncryptionPanel />);

    expect(screen.getByText(/zero-knowledge encryption active/i)).toBeInTheDocument();
  });

  it('should mention local encryption before upload', () => {
    render(<EncryptionPanel />);

    expect(screen.getByText(/encrypted locally before upload/i)).toBeInTheDocument();
  });

  it('should render lock icon', () => {
    const { container } = render(<EncryptionPanel />);

    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
  });

  it('should have green text styling', () => {
    const { container } = render(<EncryptionPanel />);

    const panel = container.firstChild as HTMLElement;
    expect(panel.className).toMatch(/text-green/);
  });

  it('should not have any toggle or password input', () => {
    render(<EncryptionPanel />);

    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/password/i)).not.toBeInTheDocument();
  });
});
