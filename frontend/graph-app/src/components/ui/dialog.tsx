import React from 'react';
import { X } from 'lucide-react';

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

export const Dialog: React.FC<DialogProps> = ({ open, onOpenChange, children }) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="fixed inset-0" onClick={() => onOpenChange(false)} />
      <div className="relative z-10 w-full max-w-xl bg-card border border-border rounded-lg shadow-2xl p-6 text-foreground max-h-[90vh] overflow-y-auto">
        <button
          type="button"
          onClick={() => onOpenChange(false)}
          className="absolute right-4 top-4 rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors cursor-pointer"
          aria-label="Close"
        >
          <X size={16} />
        </button>
        {children}
      </div>
    </div>
  );
};

export const DialogContent: React.FC<{ className?: string; children: React.ReactNode }> = ({ className = '', children }) => {
  return <div className={`dialog-content ${className}`}>{children}</div>;
};

export const DialogTitle: React.FC<{ className?: string; children: React.ReactNode }> = ({ className = '', children }) => {
  return <h2 className={`text-base font-semibold text-foreground mb-1 ${className}`}>{children}</h2>;
};

export const DialogDescription: React.FC<{ className?: string; children: React.ReactNode }> = ({ className = '', children }) => {
  return <p className={`text-xs text-muted-foreground mb-3 ${className}`}>{children}</p>;
};

export const DialogHeader: React.FC<{ className?: string; children: React.ReactNode }> = ({ className = '', children }) => {
  return <div className={`flex flex-col space-y-1 text-left ${className}`}>{children}</div>;
};

export const DialogFooter: React.FC<{ className?: string; children: React.ReactNode }> = ({ className = '', children }) => {
  return <div className={`flex items-center justify-end gap-2 mt-4 pt-3 border-t border-border ${className}`}>{children}</div>;
};
