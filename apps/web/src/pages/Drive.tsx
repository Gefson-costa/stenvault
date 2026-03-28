/**
 * Drive Page - File Management
 *
 * Thin orchestrator that delegates logic to useDrive hook
 * and renders the drive UI components.
 * Uses MobileDrive for mobile devices.
 */

import { motion, AnimatePresence } from 'framer-motion';
import { HardDrive } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { AuroraCard, AuroraCardContent } from '@/components/ui/aurora-card';
import { FadeIn } from '@/components/ui/animated';
import { FileUploader } from '@/components/FileUploader/index';
import { FileList } from '@/components/files';
import { FilePreviewModal } from '@/components/FilePreviewModal/index';
import { StorageMiniIndicator, DriveHeader } from '@/components/drive';
import { MobileDrive } from '@/components/mobile-v2/pages/MobileDrive';
import { useIsMobile } from '@/hooks/useMobile';
import { useTheme } from '@/contexts/ThemeContext';
import { VaultUnlockModal } from '@/components/VaultUnlockModal';
import { useDrive } from '@/hooks/useDrive';

export default function Drive() {
  const isMobile = useIsMobile();

  if (isMobile) {
    return <MobileDrive />;
  }

  return <DesktopDrive />;
}

function DesktopDrive() {
  const drive = useDrive();
  const { theme } = useTheme();

  return (
    <>
      <div
        className="flex flex-col h-full"
        onDragEnter={(e) => {
          e.preventDefault();
          e.stopPropagation();
          // Only show uploader for external file drags (from OS file manager)
          // Internal drags (file-to-folder) set 'fileid' type via setData('fileId', ...)
          const types = Array.from(e.dataTransfer.types);
          const isExternalFileDrag = types.includes('Files') && !types.includes('fileid');
          if (isExternalFileDrag && !drive.showUploader) drive.setShowUploader(true);
        }}
      >
        {/* Header */}
        <DriveHeader
          theme={theme}
          storageStats={drive.storageStats}
          statsLoading={drive.statsLoading}
          folderPath={drive.folderPath}
          onNavigateToFolder={drive.handleNavigateToFolder}
          viewMode={drive.viewMode}
          onViewModeChange={drive.setViewMode}
          showNewFolderDialog={drive.showNewFolderDialog}
          onNewFolderDialogChange={drive.setShowNewFolderDialog}
          newFolderName={drive.newFolderName}
          onNewFolderNameChange={drive.setNewFolderName}
          onCreateFolder={drive.handleCreateFolder}
          isCreatingFolder={drive.isCreatingFolder}
          showUploader={drive.showUploader}
          onToggleUploader={drive.toggleUploader}
        />

        {/* Upload Zone */}
        <AnimatePresence>
          {drive.showUploader && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.2 }}
              className="mb-6 overflow-hidden"
            >
              <AuroraCard
                variant="outline"
                className="relative overflow-hidden"
                style={{
                  borderStyle: 'dashed',
                  borderColor: `${theme.brand.primary}50`,
                  backgroundColor: `${theme.brand.primary}05`
                }}
              >
                <div
                  className="absolute -bottom-10 -left-10 w-24 h-24 rounded-full blur-3xl opacity-20 pointer-events-none"
                  style={{ backgroundColor: theme.brand.primary }}
                />
                <AuroraCardContent className="p-4">
                  <FileUploader
                    folderId={drive.currentFolderId}
                    onUploadComplete={drive.handleUploadComplete}
                    folderUploadMaxFiles={drive.storageStats?.folderUploadMaxFiles}
                  />
                </AuroraCardContent>
              </AuroraCard>
            </motion.div>
          )}
        </AnimatePresence>

        {/* File List */}
        <FadeIn delay={0.1} className="flex-1 min-h-0 relative">
          {/* Vault Locked Overlay */}
          {drive.isConfigured && !drive.isUnlocked && !drive.masterKeyLoading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="absolute inset-0 z-50 flex items-center justify-center backdrop-blur-md bg-background/80 rounded-lg"
            >
              <div className="text-center p-8 max-w-md">
                <motion.div
                  className="mx-auto mb-6 h-16 w-16 rounded-full flex items-center justify-center"
                  style={{ backgroundColor: `${theme.brand.primary}15` }}
                  initial={{ scale: 0.8 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 300, damping: 20 }}
                >
                  <HardDrive className="h-8 w-8" style={{ color: theme.brand.primary }} />
                </motion.div>
                <h2 className="text-xl font-semibold mb-2">Vault Locked</h2>
                <p className="text-muted-foreground mb-6">
                  Your files are encrypted. Unlock your vault with your Master Password to access them.
                </p>
                <Button
                  onClick={() => drive.setUnlockModalOpen(true)}
                  size="lg"
                  className="gap-2"
                >
                  <HardDrive className="h-4 w-4" />
                  Unlock Vault
                </Button>
              </div>
            </motion.div>
          )}

          <FileList
            folderId={drive.currentFolderId}
            onFolderClick={drive.handleFolderClick}
            onFilePreview={drive.handleFilePreview}
            onFileDownload={drive.handleFileDownload}
            onUploadRequest={() => drive.setShowUploader(true)}
          />
        </FadeIn>

        {/* File Preview Modal */}
        <FilePreviewModal
          file={drive.previewFile}
          open={!!drive.previewFile}
          onClose={() => drive.setPreviewFile(null)}
        />

        {/* Mobile Storage Indicator */}
        {!drive.statsLoading && drive.storageStats && (
          <div className="md:hidden fixed bottom-20 left-4 z-40">
            <StorageMiniIndicator
              storageUsed={drive.storageStats.storageUsed}
              storageQuota={drive.storageStats.storageQuota}
            />
          </div>
        )}
      </div>

      {/* Vault Unlock Modal */}
      <VaultUnlockModal
        isOpen={drive.unlockModalOpen}
        onUnlock={() => drive.setUnlockModalOpen(false)}
        onClose={() => drive.setUnlockModalOpen(false)}
        onForgotPassword={drive.handleForgotPassword}
      />
    </>
  );
}
