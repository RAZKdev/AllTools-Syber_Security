import React, { useEffect, useRef } from 'react';
import { AlertTriangle, X } from 'lucide-react';

interface ConfirmDialogProps {
  isOpen: boolean;
  title: string;
  message: string | React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  isDangerous?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  title,
  message,
  confirmLabel = 'Confirm & Proceed',
  cancelLabel = 'Cancel',
  isDangerous = false,
  onConfirm,
  onCancel,
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);
  const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!isOpen) return;

    // Save current active element to restore focus upon dismissal
    previouslyFocusedElementRef.current = document.activeElement as HTMLElement;

    // Focus cancel button on open (safe default for high-impact actions)
    const timer = setTimeout(() => {
      cancelButtonRef.current?.focus();
    }, 50);

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCancel();
        return;
      }

      // Focus trap containment for Tab and Shift+Tab
      if (e.key === 'Tab' && modalRef.current) {
        const focusableElements = modalRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusableElements.length === 0) return;

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            e.preventDefault();
            lastElement.focus();
          }
        } else {
          if (document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);

    return () => {
      clearTimeout(timer);
      window.removeEventListener('keydown', handleKeyDown);
      // Restore focus to invoking control
      if (previouslyFocusedElementRef.current && typeof previouslyFocusedElementRef.current.focus === 'function') {
        previouslyFocusedElementRef.current.focus();
      }
    };
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  return (
    <div
      className="wb-modal-backdrop"
      onClick={onCancel}
      aria-hidden="false"
    >
      <div
        ref={modalRef}
        className="wb-modal"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-message"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="wb-modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle
              size={16}
              color={isDangerous ? 'var(--status-fail-text)' : 'var(--status-warn-text)'}
            />
            <span id="confirm-dialog-title" style={{ fontWeight: 700, fontSize: '12px' }}>
              {title}
            </span>
          </div>
          <button
            onClick={onCancel}
            style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}
            title="Close dialog (Escape)"
            aria-label="Close dialog"
          >
            <X size={16} />
          </button>
        </div>

        <div id="confirm-dialog-message" className="wb-modal-body">
          {typeof message === 'string' ? (
            <p style={{ margin: 0, color: 'var(--text-primary)' }}>{message}</p>
          ) : (
            message
          )}
        </div>

        <div className="wb-modal-footer">
          <button
            ref={cancelButtonRef}
            className="wb-btn"
            onClick={onCancel}
          >
            {cancelLabel}
          </button>
          <button
            className={`wb-btn ${isDangerous ? 'wb-btn-danger' : 'wb-btn-primary'}`}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};
