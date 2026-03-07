/**
 * Lightweight notification singleton.
 * Drop-in replacement for @mantine/notifications so all pages keep working
 * after the Mantine → CoreUI migration.
 *
 * DefaultLayout subscribes on mount and renders toasts via CoreUI.
 */

const listeners = new Set()

/** Map Mantine colour names to Bootstrap/CoreUI colour names */
const COLOUR_MAP = {
  teal:   'success',
  green:  'success',
  red:    'danger',
  orange: 'warning',
  yellow: 'warning',
  blue:   'info',
  violet: 'info',
  gray:   'secondary',
  grey:   'secondary',
}

function normalise(color) {
  return COLOUR_MAP[color] ?? color ?? 'primary'
}

export const notifications = {
  /** @param {{ message: string, title?: string, color?: string }} opts */
  show({ message, title, color = 'success' }) {
    const toast = { id: Date.now() + Math.random(), message, title, color: normalise(color) }
    listeners.forEach(fn => fn(toast))
  },
}

/** Called by DefaultLayout to start receiving toast events. Returns unsubscribe fn. */
export function subscribeToasts(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}
