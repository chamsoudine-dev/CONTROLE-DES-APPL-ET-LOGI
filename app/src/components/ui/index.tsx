// Petits composants dans l'esprit shadcn/ui (copiés localement, sans dépendance distante).
import * as React from "react";
import { cn } from "@/lib/utils";

type ButtonVariant = "default" | "outline" | "ghost" | "destructive" | "secondary" | "link";
const variants: Record<ButtonVariant, string> = {
  default: "bg-primary text-primary-foreground hover:opacity-90",
  outline: "border bg-transparent hover:bg-muted",
  ghost: "hover:bg-muted",
  destructive: "bg-destructive text-destructive-foreground hover:opacity-90",
  secondary: "bg-muted text-foreground hover:opacity-80",
  link: "underline-offset-4 hover:underline text-primary",
};

export const Button = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: "sm" | "md" }
>(({ className, variant = "default", size = "md", ...props }, ref) => (
  <button
    ref={ref}
    className={cn(
      "inline-flex items-center justify-center gap-2 rounded-md font-medium transition disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2",
      size === "sm" ? "h-8 px-3 text-sm" : "h-10 px-4 text-sm",
      variants[variant],
      className,
    )}
    {...props}
  />
));
Button.displayName = "Button";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      autoComplete="off"
      spellCheck={false}
      className={cn(
        "h-10 w-full rounded-md border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-primary focus-ring-offset-2",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";

export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      spellCheck={false}
      {...props}
      className={cn(
        "w-full rounded-md border bg-background p-3 font-mono text-sm outline-none focus:ring-2 focus:ring-primary",
        props.className,
      )}
    />
  );
}
Textarea.displayName = "Textarea";

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={cn("h-10 w-full rounded-md border bg-background px-3 text-sm", props.className)}
    />
  );
}

export function Label({ children, className }: { children: React.ReactNode; className?: string }) {
  return <label className={cn("mb-1 block text-sm font-medium", className)}>{children}</label>;
}

export function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <div className="space-y-1">
      <Label>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function Card({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("rounded-lg border bg-card p-5 text-card-foreground shadow-sm", className)}>{children}</div>;
}

export function CardTitle({ children, actions }: { children: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h2 className="text-lg font-semibold">{children}</h2>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

type Tone = "default" | "success" | "warning" | "destructive" | "muted";
const tones: Record<Tone, string> = {
  default: "bg-primary/10 text-primary",
  success: "bg-success/15 text-success",
  warning: "bg-warning/15 text-warning",
  destructive: "bg-destructive/15 text-destructive",
  muted: "bg-muted text-muted-foreground",
};
export function Badge({ tone = "default", children }: { tone?: Tone; children: React.ReactNode }) {
  return <span className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium", tones[tone])}>{children}</span>;
}

export function Alert({ tone = "default", children }: { tone?: Tone; children: React.ReactNode }) {
  return (
    <div className={cn("rounded-md px-3 py-2 text-sm", tones[tone])} role="alert">
      {children}
    </div>
  );
}

export function Modal({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="max-h-[90vh] w-full max-w-lg overflow-auto rounded-lg border bg-card p-5 shadow-lg" role="document">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold">{title}</h3>
          <button className="text-muted-foreground hover:text-foreground" onClick={onClose} aria-label="Fermer">✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Spinner() {
  return <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />;
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="py-6 text-center text-sm text-muted-foreground">{children}</p>;
}

/* NEW: Toast component */
type ToastVariant = "default" | "success" | "warning" | "destructive";
const toastVariants: Record<ToastVariant, string> = {
  default: "bg-card text-card-foreground",
  success: "bg-success/20 text-success",
  warning: "bg-warning/20 text-warning",
  destructive: "bg-destructive/20 text-destructive",
};

type ToastAction = { label: string; onClick: () => void };
export function Toast({
  title,
  description,
  variant = "default",
  action,
  duration = 5000,
}: {
  title: string;
  description?: string;
  variant?: ToastVariant;
  action?: ToastAction;
  duration?: number;
}) {
  const [isVisible, setVisible] = React.useState(true);
  const [hasAutoClosed, setAutoClosed] = React.useState(false);

  React.useEffect(() => {
    const timer = setTimeout(() => setVisible(false), duration);
    return () => clearTimeout(timer);
  }, [duration, setVisible]);

  if (!isVisible && hasAutoClosed) return null;

  return (
    <div
      className={cn(
        "fixed bottom-4 right-4 flex items-center gap-3 rounded-lg px-5 py-3 shadow-lg z-50 transform translate-y-0 transition-transform duration-300 ease-out border",
        "border-t-4",
        toastVariants[variant],
      )}
    >
      <div className="flex-1 min-w-0">
        <p className="font-medium truncate">{title}</p>
        {description && <p className="text-sm truncate opacity-90">{description}</p>}
      </div>
      {action && (
        <button
          className="ml-3 rounded-md px-2 py-1 text-xs font-medium transition-colors hover:opacity-80"
          onClick={() => {
            action.onClick();
            setAutoClosed(true);
          }}
        >
          {action.label}
        </button>
      )}
    </div>
  );
}

/* NEW: Tooltip component */
export function Tooltip({
  children,
  title,
}: {
  children: React.ReactNode;
  title: string;
}) {
  return (
    <div className="relative inline-flex items-center">
      {children}
      <div
        role="tooltip"
        className="hidden bg-muted text-muted-foreground text-xs rounded-md px-2 py-1 shadow-sm opacity-0 transition-opacity duration-200 ease-out transform -translate-y-1 border border-muted/50"
        style={{ opacity: 0, transform: 'translateY(4px)' }}
      >
        {title}
      </div>
    </div>
  );
}

/* NEW: Skeleton component */
export function Skeleton({
  className,
  animated = true,
}: {
  className?: string;
  animated?: boolean;
}) {
  const baseClasses = cn(
    "h-8 rounded-md bg-m placeholder:bg-muted/50 animate-pulse",
    className,
  );
  if (!animated) return <span className={baseClasses} />;
  return (
    <div
      className={cn(
        "animate-bounce bg-gradient-to-b from-transparent via-[var(--m)] to-transparent",
        "bg-conic-gradient(from 90deg, transparent, var(--m), transparent)",
        baseClasses,
      )}
    />
  );
}

/* NEW: StatCard */
export function StatCard({ value, label, subtitle, icon, className }: {
  value: string | number;
  label: string;
  subtitle?: string;
  icon?: React.ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn(className, "h-full flex flex-col justify-between")}>
      {icon && <div className="flex justify-center mb-3">{icon}</div>}
      <div>
        <p className="text-sm font-medium truncate">{label}</p>
        <p className="text-2xl font-bold">{typeof value === "number" ? value : value}</p>
      </div>
      {subtitle && <p className="text-xs text-muted-foreground truncate">{subtitle}</p>}
    </Card>
  );
}

/* NEW: EmptyState with illustration */
export function EmptyState({
  title,
  description,
  illustration,
  action,
  className,
}: {
  title: string;
  description?: string;
  illustration?: string;
  action?: { label: string; onClick: () => void };
  className?: string;
}) {
  return (
    <Card className={cn(className, "text-center py-12")}>
      {illustration && <img src={illustration} alt="" className="mx-auto h-24 w-24 opacity-50 mb-4" />}
      <h3 className="text-xl font-semibold mb-2">{title}</h3>
      {description && <p className="text-muted-foreground mb-6">{description}</p>}
      {action && (
        <Button
          variant="outline"
          size="sm"
          className="mx-auto"
          onClick={action.onClick}
        >
          {action.label}
        </Button>
      )}
    </Card>
  );
}