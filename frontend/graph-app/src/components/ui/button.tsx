import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className = '', variant = 'default', size = 'default', children, ...props }, ref) => {
    let base = 'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded font-medium cursor-pointer transition-colors focus-visible:outline-none focus-visible:ring-1 disabled:pointer-events-none disabled:opacity-50 text-xs border';

    let variantClasses = 'bg-primary text-primary-foreground border-transparent hover:opacity-90';
    if (variant === 'destructive') variantClasses = 'bg-destructive text-destructive-foreground border-transparent hover:opacity-90';
    else if (variant === 'outline') variantClasses = 'border-border bg-card text-foreground hover:bg-muted';
    else if (variant === 'secondary') variantClasses = 'bg-secondary text-secondary-foreground border-transparent hover:bg-muted';
    else if (variant === 'ghost') variantClasses = 'border-transparent text-muted-foreground hover:bg-muted hover:text-foreground';
    else if (variant === 'link') variantClasses = 'border-transparent text-primary underline-offset-4 hover:underline';

    let sizeClasses = 'h-8 px-3 py-1';
    if (size === 'sm') sizeClasses = 'h-7 px-2.5 py-0.5 text-[11px]';
    else if (size === 'lg') sizeClasses = 'h-10 px-5 text-sm';
    else if (size === 'icon') sizeClasses = 'h-8 w-8 p-0';

    return (
      <button ref={ref} className={`${base} ${variantClasses} ${sizeClasses} ${className}`} {...props}>
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
