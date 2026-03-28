/**
 * Drive Page - Query Param Parsing Tests
 *
 * Tests URL-synced query param behavior in isolation
 * (without mounting the full Drive component which is heavy).
 *
 * Validates the exact parsing logic used by useDrive hook:
 * - view param -> ViewMode
 * - q param -> search query
 * - action param -> triggers upload/new-folder
 */

import { describe, it, expect } from 'vitest';
import { parseDriveParams, buildDriveUrl } from '@/hooks/useDrive';

describe('Drive query param parsing', () => {
  describe('View mode extraction', () => {
    it('should default to stored view mode when no param', () => {
      const { viewMode } = parseDriveParams('');
      expect(viewMode).toBe('grid');
    });

    it('should default to list when stored is list', () => {
      const { viewMode } = parseDriveParams('', 'list');
      expect(viewMode).toBe('list');
    });

    it('should extract view=list from query', () => {
      const { viewMode } = parseDriveParams('view=list');
      expect(viewMode).toBe('list');
    });

    it('should extract view=grid from query', () => {
      const { viewMode } = parseDriveParams('view=grid');
      expect(viewMode).toBe('grid');
    });

    it('should override stored mode with URL param', () => {
      const { viewMode } = parseDriveParams('view=list', 'grid');
      expect(viewMode).toBe('list');
    });
  });

  describe('Search query extraction', () => {
    it('should default to empty string when no q param', () => {
      const { searchQuery } = parseDriveParams('');
      expect(searchQuery).toBe('');
    });

    it('should extract q param', () => {
      const { searchQuery } = parseDriveParams('q=test-search');
      expect(searchQuery).toBe('test-search');
    });

    it('should handle URL-encoded search', () => {
      const { searchQuery } = parseDriveParams('q=hello%20world');
      expect(searchQuery).toBe('hello world');
    });

    it('should handle combined params', () => {
      const { viewMode, searchQuery } = parseDriveParams('view=list&q=photos');
      expect(viewMode).toBe('list');
      expect(searchQuery).toBe('photos');
    });
  });

  describe('Action param extraction', () => {
    it('should return null when no action', () => {
      const { action } = parseDriveParams('');
      expect(action).toBeNull();
    });

    it('should extract action=upload', () => {
      const { action } = parseDriveParams('action=upload');
      expect(action).toBe('upload');
    });

    it('should extract action=new-folder', () => {
      const { action } = parseDriveParams('action=new-folder');
      expect(action).toBe('new-folder');
    });

    it('should handle action with other params', () => {
      const { action, viewMode } = parseDriveParams('view=grid&action=upload');
      expect(action).toBe('upload');
      expect(viewMode).toBe('grid');
    });
  });

  describe('URL building', () => {
    it('should build URL with view param', () => {
      const url = buildDriveUrl('', { view: 'list' });
      expect(url).toBe('/drive?view=list');
    });

    it('should build URL with search query', () => {
      const url = buildDriveUrl('', { q: 'photos' });
      expect(url).toBe('/drive?q=photos');
    });

    it('should remove q when empty', () => {
      const url = buildDriveUrl('q=photos', { q: '' });
      expect(url).toBe('/drive');
    });

    it('should preserve existing params when setting view', () => {
      const url = buildDriveUrl('q=docs', { view: 'list' });
      expect(url).toContain('q=docs');
      expect(url).toContain('view=list');
    });

    it('should return clean URL when no params', () => {
      const url = buildDriveUrl('', {});
      expect(url).toBe('/drive');
    });

    it('should update existing view param', () => {
      const url = buildDriveUrl('view=grid', { view: 'list' });
      expect(url).toBe('/drive?view=list');
    });
  });
});
