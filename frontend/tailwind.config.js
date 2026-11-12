/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Professional SaaS Blue primary palette
        primary: {
          50: '#eff6ff', 100: '#dbeafe', 200: '#bfdbfe', 300: '#93c5fd', 400: '#60a5fa',
          500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8', 800: '#1e40af', 900: '#1e3a8a', 950: '#172554',
        },
        // Alias cyber to primary for backward compatibility
        cyber: {
          50: '#eff6ff', 100: '#dbeafe', 200: '#bfdbfe', 300: '#93c5fd', 400: '#3b82f6',
          500: '#2563eb', 600: '#1d4ed8', 700: '#1e40af', 800: '#1e3a8a', 900: '#172554', 950: '#0f172a',
        },
        // Clean neutral light surfaces
        surface: {
          50: '#ffffff', 100: '#f8fafc', 200: '#f1f5f9', 300: '#e2e8f0', 400: '#cbd5e1',
          500: '#94a3b8', 600: '#64748b', 700: '#475569', 800: '#1e293b', 900: '#0f172a', 950: '#020617',
        },
        // Risk colours
        risk: {
          critical: '#e11d48', high: '#ea580c', medium: '#d97706', low: '#16a34a', info: '#64748b',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      keyframes: {
        'fade-in':   { from: { opacity: 0 }, to: { opacity: 1 } },
        'fade-out':  { from: { opacity: 1 }, to: { opacity: 0 } },
        'slide-up':  { from: { opacity: 0, transform: 'translateY(8px)' }, to: { opacity: 1, transform: 'translateY(0)' } },
        'pop-in':    { from: { opacity: 0, transform: 'scale(.97) translateY(6px)' }, to: { opacity: 1, transform: 'scale(1) translateY(0)' } },
        'pop-out':   { from: { opacity: 1, transform: 'scale(1)' }, to: { opacity: 0, transform: 'scale(.97)' } },
        'slide-in-right':  { from: { transform: 'translateX(24px)', opacity: 0 }, to: { transform: 'translateX(0)', opacity: 1 } },
        'slide-out-right': { from: { transform: 'translateX(0)', opacity: 1 }, to: { transform: 'translateX(24px)', opacity: 0 } },
        shimmer: { '100%': { transform: 'translateX(100%)' } },
      },
      animation: {
        'fade-in': 'fade-in .25s ease-out both',
        'fade-out': 'fade-out .18s ease-in both',
        'slide-up': 'slide-up .3s ease-out both',
        'pop-in': 'pop-in .2s ease-out both',
        'pop-out': 'pop-out .18s ease-in both',
        'slide-in-right': 'slide-in-right .25s ease-out both',
        'slide-out-right': 'slide-out-right .18s ease-in both',
      },
    },
  },
  plugins: [],
}
