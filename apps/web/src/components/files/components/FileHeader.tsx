/**
 * FileHeader Component
 * 
 * Header for FileList with breadcrumbs, view toggle, and filters.
 */

import { useState } from 'react';
import { ChevronRight, Grid3X3, List, Images, Search, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { FilterPanel, type FileFilters } from '@/components/filters/FilterPanel';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import type { ViewMode, BreadcrumbItem } from '../types';
interface FileHeaderProps {
    breadcrumbs: BreadcrumbItem[];
    viewMode: ViewMode;
    onViewModeChange: (mode: ViewMode) => void;
    filters: FileFilters;
    onFiltersChange: (filters: FileFilters) => void;
    onFolderClick?: (folderId: number) => void;
}

export function FileHeader({
    breadcrumbs,
    viewMode,
    onViewModeChange,
    filters,
    onFiltersChange,
    onFolderClick,
}: FileHeaderProps) {
    const [mobileSearchOpen, setMobileSearchOpen] = useState(false);

    const activeFilterCount =
        filters.fileTypes.length +
        (filters.dateRange !== 'all' ? 1 : 0) +
        (filters.minSize !== undefined || filters.maxSize !== undefined ? 1 : 0) +
        filters.tags.length +
        (filters.searchQuery && filters.searchQuery.trim().length > 0 ? 1 : 0);

    return (
        <>
            {/* Mobile search bar */}
            {mobileSearchOpen && (
                <div className="flex items-center gap-2 md:hidden mb-2">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                            type="text"
                            placeholder="Search files..."
                            value={filters.searchQuery || ''}
                            onChange={(e) => onFiltersChange({ ...filters, searchQuery: e.target.value })}
                            className="pl-9 pr-8"
                            autoFocus
                        />
                        {filters.searchQuery && filters.searchQuery.trim() && (
                            <button
                                onClick={() => onFiltersChange({ ...filters, searchQuery: '' })}
                                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        )}
                    </div>
                    <Button variant="ghost" size="icon" onClick={() => { setMobileSearchOpen(false); onFiltersChange({ ...filters, searchQuery: '' }); }}>
                        <X className="w-4 h-4" />
                    </Button>
                </div>
            )}

            <div className="flex items-center justify-between">
                {/* Breadcrumbs */}
                <nav className="flex items-center space-x-1 text-sm overflow-x-auto scrollbar-none max-w-[50vw] md:max-w-none" aria-label="Folder navigation">
                    <ol className="flex items-center space-x-1 whitespace-nowrap">
                        {breadcrumbs.map((crumb, index) => {
                            const isCurrentPage = index === breadcrumbs.length - 1;
                            return (
                                <li key={crumb.id ?? 'root'} className="flex items-center">
                                    {index > 0 && <ChevronRight className="w-4 h-4 mx-1 text-muted-foreground" aria-hidden="true" />}
                                    <button
                                        onClick={() => crumb.id !== null && onFolderClick?.(crumb.id)}
                                        className={cn(
                                            'px-2 py-1 rounded hover:bg-accent transition-colors',
                                            isCurrentPage ? 'font-medium text-foreground' : 'text-muted-foreground'
                                        )}
                                        disabled={isCurrentPage}
                                        aria-current={isCurrentPage ? 'page' : undefined}
                                    >
                                        {crumb.name}
                                    </button>
                                </li>
                            );
                        })}
                    </ol>
                </nav>

                {/* Search Input - Phase 5 Zero-Knowledge */}
                <div className="flex-1 max-w-xs mx-4 hidden md:block">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                            type="text"
                            placeholder="Search files..."
                            value={filters.searchQuery || ''}
                            onChange={(e) => onFiltersChange({ ...filters, searchQuery: e.target.value })}
                            className="pl-9 pr-8 h-9"
                        />
                        {filters.searchQuery && filters.searchQuery.trim() && (
                            <button
                                onClick={() => onFiltersChange({ ...filters, searchQuery: '' })}
                                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        )}
                    </div>
                </div>

                {/* Mobile search toggle */}
                <Button
                    variant="ghost"
                    size="icon"
                    className="md:hidden h-9 w-9"
                    onClick={() => setMobileSearchOpen(!mobileSearchOpen)}
                    aria-label="Search files"
                >
                    <Search className="w-4 h-4" />
                </Button>

                {/* Actions */}
                <div className="flex items-center gap-2">
                    {/* Filter Panel */}
                    <FilterPanel
                        filters={filters}
                        onFiltersChange={onFiltersChange}
                        activeFilterCount={activeFilterCount}
                    />

                    {/* View toggle */}
                    <div className="flex items-center gap-1 p-1 rounded-lg bg-secondary/50" role="group" aria-label="View mode">
                        <Button
                            variant={viewMode === 'grid' ? 'secondary' : 'ghost'}
                            size="icon"
                            className="h-8 w-8"
                            onClick={() => onViewModeChange('grid')}
                            aria-label="Grid view"
                            aria-pressed={viewMode === 'grid'}
                        >
                            <Grid3X3 className="w-4 h-4" aria-hidden="true" />
                        </Button>
                        <Button
                            variant={viewMode === 'list' ? 'secondary' : 'ghost'}
                            size="icon"
                            className="h-8 w-8"
                            onClick={() => onViewModeChange('list')}
                            aria-label="List view"
                            aria-pressed={viewMode === 'list'}
                        >
                            <List className="w-4 h-4" aria-hidden="true" />
                        </Button>
                        <Button
                            variant={viewMode === 'gallery' ? 'secondary' : 'ghost'}
                            size="icon"
                            className="h-8 w-8"
                            onClick={() => onViewModeChange('gallery')}
                            aria-label="Gallery view"
                            aria-pressed={viewMode === 'gallery'}
                        >
                            <Images className="w-4 h-4" aria-hidden="true" />
                        </Button>
                    </div>
                </div>
            </div>

        </>
    );
}
