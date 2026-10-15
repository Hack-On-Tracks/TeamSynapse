import React from 'react';
import { X } from 'lucide-react';

export interface SheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

export const Sheet: React.FC<SheetProps> = ({ open, onOpenChange, children }) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/30 backdrop-blur-[2px] animate-in fade-in duration-150">
      <div className="fixed inset-0" onClick={() => onOpenChange(false)} />
      <div className="relative z-10 w-full max-w-lg bg-card border-l border-border shadow-2xl p-6 text-foreground h-full overflow-y-auto">
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

export const SheetContent: React.FC<{ className?: string; children: React.ReactNode }> = ({ className = '', children }) => {
  return <div className={`sheet-content ${className}`}>{children}</div>;
};

export const SheetTitle: React.FC<{ className?: string; children: React.ReactNode }> = ({ className = '', children }) => {
  return <h2 className={`text-base font-semibold text-foreground ${className}`}>{children}</h2>;
};

export const SheetDescription: React.FC<{ className?: string; children: React.ReactNode }> = ({ className = '', children }) => {
  return <p className={`text-xs text-muted-foreground ${className}`}>{children}</p>;
};
