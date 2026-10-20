import '@testing-library/jest-dom'

// Polyfill ResizeObserver for jsdom (used by recharts ResponsiveContainer)
if (typeof window !== 'undefined' && typeof window.ResizeObserver === 'undefined') {
  class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  window.ResizeObserver = ResizeObserver
}