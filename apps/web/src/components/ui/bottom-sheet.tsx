/**
 * BottomSheet Component
 *
 * Design System: Obsidian Vault
 * Mobile-friendly bottom sheet with smooth animations.
 */

import * as React from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { useIsMobile } from "@/hooks/useMobile";

const BottomSheet = DialogPrimitive.Root;
const BottomSheetTrigger = DialogPrimitive.Trigger;
const BottomSheetClose = DialogPrimitive.Close;
const BottomSheetPortal = DialogPrimitive.Portal;

// ─────────────────────────────────────────────────────────────
// BOTTOM SHEET OVERLAY
// ─────────────────────────────────────────────────────────────

const BottomSheetOverlay = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Overlay>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Overlay>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Overlay
    ref={ref}
    className={cn(
      "fixed inset-0 z-50",
      "bg-black/60 backdrop-blur-sm",
      "data-[state=open]:animate-in data-[state=closed]:animate-out",
      "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
      className
    )}
    {...props}
  />
));

BottomSheetOverlay.displayName = "BottomSheetOverlay";

// ─────────────────────────────────────────────────────────────
// BOTTOM SHEET CONTENT
// ─────────────────────────────────────────────────────────────

interface BottomSheetContentProps
  extends React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> {
  /**
   * Whether to show the drag handle
   */
  showHandle?: boolean;
  /**
   * Whether to show the close button
   */
  showCloseButton?: boolean;
  /**
   * Max height on desktop (mobile is always from bottom)
   */
  maxHeight?: string;
}

const BottomSheetContent = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  BottomSheetContentProps
>(({
  className,
  children,
  showHandle = true,
  showCloseButton = true,
  maxHeight = "85vh",
  ...props
}, ref) => {
  const isMobile = useIsMobile();
  const [dragPosition, setDragPosition] = React.useState(0);
  const isDragging = React.useRef(false);
  const startY = React.useRef(0);

  const handleDragStart = (e: React.TouchEvent | React.MouseEvent) => {
    isDragging.current = true;
    const clientY = 'touches' in e
      ? (e.touches[0]?.clientY ?? 0)
      : (e as React.MouseEvent).clientY;
    startY.current = clientY;
  };

  const handleDragMove = (e: React.TouchEvent | React.MouseEvent) => {
    if (!isDragging.current) return;
    const clientY = 'touches' in e
      ? (e.touches[0]?.clientY ?? 0)
      : (e as React.MouseEvent).clientY;
    const deltaY = clientY - startY.current;
    if (deltaY > 0) {
      setDragPosition(deltaY);
    }
  };

  const handleDragEnd = () => {
    isDragging.current = false;
    if (dragPosition > 100) {
      // Close if dragged down more than 100px
      const closeButton = document.querySelector('[data-bottom-sheet-close]') as HTMLElement;
      closeButton?.click();
    }
    setDragPosition(0);
  };

  return (
    <BottomSheetPortal>
      <BottomSheetOverlay />
      <DialogPrimitive.Content
        ref={ref}
        className={cn(
          "fixed z-50",
          "bg-card/95 backdrop-blur-xl",
          "border border-border",
          "shadow-2xl shadow-black/20",
          "flex flex-col overflow-hidden",
          // Mobile: bottom sheet from bottom
          isMobile && [
            "bottom-0 left-0 right-0",
            "rounded-t-2xl",
            "max-h-[85vh]",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "data-[state=closed]:slide-out-to-bottom data-[state=open]:slide-in-from-bottom",
          ],
          // Desktop: centered dialog
          !isMobile && [
            "top-[50%] left-[50%]",
            "translate-x-[-50%] translate-y-[-50%]",
            "rounded-xl",
            "w-full max-w-lg",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
            "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
            "data-[state=closed]:slide-out-to-left-1/2 data-[state=closed]:slide-out-to-top-[48%]",
            "data-[state=open]:slide-in-from-left-1/2 data-[state=open]:slide-in-from-top-[48%]",
          ],
          "duration-300",
          className
        )}
        style={isMobile ? {
          transform: `translateY(${dragPosition}px)`,
          maxHeight,
        } : { maxHeight }}
        {...props}
      >
        {/* Drag handle for mobile */}
        {showHandle && isMobile && (
          <div
            className="flex justify-center pt-3 pb-2 cursor-grab active:cursor-grabbing"
            onTouchStart={handleDragStart}
            onTouchMove={handleDragMove}
            onTouchEnd={handleDragEnd}
            onMouseDown={handleDragStart}
            onMouseMove={handleDragMove}
            onMouseUp={handleDragEnd}
          >
            <div className="w-12 h-1 rounded-full bg-border" />
          </div>
        )}

        {/* Content — each child (Header, Body, Footer) manages its own scroll */}
        {children}

        {/* Close button */}
        {showCloseButton && (
          <DialogPrimitive.Close
            data-bottom-sheet-close
            className={cn(
              "absolute top-4 right-4",
              "p-1.5 rounded-lg",
              "text-foreground-muted hover:text-foreground",
              "hover:bg-secondary",
              "transition-colors",
              "focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            )}
          >
            <X className="h-4 w-4" />
            <span className="sr-only">Close</span>
          </DialogPrimitive.Close>
        )}
      </DialogPrimitive.Content>
    </BottomSheetPortal>
  );
});

BottomSheetContent.displayName = "BottomSheetContent";

// ─────────────────────────────────────────────────────────────
// BOTTOM SHEET HEADER
// ─────────────────────────────────────────────────────────────

const BottomSheetHeader = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      "flex flex-col gap-2 p-6 pb-4 shrink-0",
      className
    )}
    {...props}
  />
);

BottomSheetHeader.displayName = "BottomSheetHeader";

// ─────────────────────────────────────────────────────────────
// BOTTOM SHEET TITLE
// ─────────────────────────────────────────────────────────────

const BottomSheetTitle = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Title>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Title
    ref={ref}
    className={cn(
      "font-display text-xl tracking-tight text-foreground",
      className
    )}
    {...props}
  />
));

BottomSheetTitle.displayName = "BottomSheetTitle";

// ─────────────────────────────────────────────────────────────
// BOTTOM SHEET DESCRIPTION
// ─────────────────────────────────────────────────────────────

const BottomSheetDescription = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Description>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Description
    ref={ref}
    className={cn("text-sm text-foreground-muted", className)}
    {...props}
  />
));

BottomSheetDescription.displayName = "BottomSheetDescription";

// ─────────────────────────────────────────────────────────────
// BOTTOM SHEET BODY
// ─────────────────────────────────────────────────────────────

const BottomSheetBody = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("px-6 pb-6 overflow-y-auto flex-1 min-h-0", className)} {...props} />
);

BottomSheetBody.displayName = "BottomSheetBody";

// ─────────────────────────────────────────────────────────────
// BOTTOM SHEET FOOTER
// ─────────────────────────────────────────────────────────────

const BottomSheetFooter = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      "flex flex-col-reverse gap-2 px-6 pb-6 shrink-0",
      "sm:flex-row sm:justify-end",
      className
    )}
    {...props}
  />
);

BottomSheetFooter.displayName = "BottomSheetFooter";

export {
  BottomSheet,
  BottomSheetTrigger,
  BottomSheetClose,
  BottomSheetContent,
  BottomSheetHeader,
  BottomSheetTitle,
  BottomSheetDescription,
  BottomSheetBody,
  BottomSheetFooter,
};
