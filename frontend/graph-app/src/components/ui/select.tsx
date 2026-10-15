import React, { createContext, useContext, useState, useRef, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';

interface SelectContextType {
  value: string;
  onValueChange?: (val: string) => void;
  open: boolean;
  setOpen: React.Dispatch<React.SetStateAction<boolean>>;
}

const SelectContext = createContext<SelectContextType>({
  value: '',
  open: false,
  setOpen: () => {},
});

export const Select: React.FC<{
  value: string;
  onValueChange?: (value: string) => void;
  children: React.ReactNode;
}> = ({ value, onValueChange, children }) => {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <SelectContext.Provider value={{ value, onValueChange, open, setOpen }}>
      <div ref={containerRef} className="relative inline-block text-left">
        {children}
      </div>
    </SelectContext.Provider>
  );
};

export const SelectTrigger: React.FC<{
  className?: string;
  children: React.ReactNode;
  'aria-label'?: string;
}> = ({ className = '', children, 'aria-label': ariaLabel }) => {
  const { open, setOpen } = useContext(SelectContext);
  return (
    <button
      type="button"
      aria-label={ariaLabel}
      onClick={() => setOpen(!open)}
      className={`inline-flex items-center justify-between border border-border bg-card rounded px-2.5 py-1 text-xs text-foreground cursor-pointer hover:bg-muted focus:outline-none ${className}`}
    >
      <div className="flex items-center gap-1.5">{children}</div>
      <ChevronDown size={12} className="ml-1 opacity-60" />
    </button>
  );
};

export const SelectValue: React.FC<{ placeholder?: string }> = ({ placeholder = '' }) => {
  const { value } = useContext(SelectContext);
  return <span>{value || placeholder}</span>;
};

export const SelectContent: React.FC<{ className?: string; children: React.ReactNode }> = ({
  className = '',
  children,
}) => {
  const { open } = useContext(SelectContext);
  if (!open) return null;

  return (
    <div
      className={`absolute left-0 mt-1 z-50 min-w-[8rem] overflow-hidden rounded border border-border bg-card p-1 text-foreground shadow-lg animate-in fade-in-80 ${className}`}
    >
      {children}
    </div>
  );
};

export const SelectItem: React.FC<{
  value: string;
  children: React.ReactNode;
  className?: string;
}> = ({ value, children, className = '' }) => {
  const { value: selectedValue, onValueChange, setOpen } = useContext(SelectContext);
  const isSelected = selectedValue === value;

  return (
    <div
      role="option"
      aria-selected={isSelected}
      onClick={() => {
        onValueChange?.(value);
        setOpen(false);
      }}
      className={`relative flex cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-xs outline-none hover:bg-accent hover:text-accent-foreground ${
        isSelected ? 'bg-secondary font-medium' : ''
      } ${className}`}
    >
      {children}
    </div>
  );
};
