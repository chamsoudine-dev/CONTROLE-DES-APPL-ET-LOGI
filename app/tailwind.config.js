/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class", "[data-theme='dark']", "[data-theme='light']"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    container: {
      center: true,
      padding: {
        DEFAULT: "2rem",
        sm: "2rem",
        lg: "4rem",
        xl: "6rem",
        "2xl": "8rem",
      },
    },
    extend: {
      colors: {
        border: "var(--color-border, hsl(var(--border)))",
        background: "var(--color-background, hsl(var(--background)))",
        foreground: "var(--color-foreground, hsl(var(--foreground)))",
        muted: {
          DEFAULT: "var(--color-muted, hsl(var(--muted)))",
          foreground: "var(--color-muted-foreground, hsl(var(--muted-foreground)))",
        },
        primary: {
          DEFAULT: "var(--color-primary, hsl(var(--primary)))",
          foreground: "var(--color-primary-foreground, hsl(var(--primary-foreground)))",
        },
        destructive: {
          DEFAULT: "var(--color-destructive, hsl(var(--destructive)))",
          foreground: "var(--color-destructive-foreground, hsl(var(--destructive-foreground)))",
        },
        card: {
          DEFAULT: "var(--color-card, hsl(var(--card)))",
          foreground: "var(--color-card-foreground, hsl(var(--card-foreground)))",
        },
        success: "var(--color-success, hsl(var(--success)))",
        warning: "var(--color-warning, hsl(var(--warning)))",
      },
      borderRadius: {
        lg: "var(--radius-lg, 0.6rem)",
        md: "var(--radius-md, 0.45rem)",
        sm: "var(--radius-sm, 0.3rem)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: 0 },
          to: { height: "var(--radix-accordion-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-height)" },
          to: { height: 0 },
        },
        "caret-blink": {
          "0%, 70%, 100%": { opacity: "1" },
          "20%, 40%, 60%": { opacity: "0.75" },
        },
        "accordion-pop": {
          from: { scale: 0.95 },
          to: { scale: 1 },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "caret-blink": "caret-blink 1.2s ease-out infinite",
      },
    },
  },
  plugins: [
    require("tailwindcss-animate"),
    function ({ addUtilities }: any) {
      addUtilities({
        ".bg-pattern-grid": {
          "background-image": "url(\"data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M0 30h30M30 0v30M30 60h30M60 30v30' stroke='%23e5e7eb' stroke-width='1'/%3E%3C/svg%3E\")",
          "background-size": "60px 60px",
        },
        ".bg-pattern-subtle": {
          "background-image": "url(\"data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23f3f4f6' fill-opacity='0.3'%3E%3Cpath d='M0 0h100v100H0V0Z'/%3E%3C/g%3E%3C/svg%3E\")",
          "background-size": "100px 100px",
        },
      }, {
        safety: false,
      });
    },
  ],
};