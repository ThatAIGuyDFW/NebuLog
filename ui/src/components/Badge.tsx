import clsx from 'clsx'
import type { Severity, AlertStatus } from '../api/types'

const SEVERITY_CLASSES: Record<Severity, string> = {
  critical: 'bg-red-950 text-red-400 border-red-800',
  high:     'bg-orange-950 text-orange-400 border-orange-800',
  medium:   'bg-yellow-950 text-yellow-400 border-yellow-800',
  low:      'bg-blue-950 text-blue-400 border-blue-800',
  info:     'bg-gray-800 text-gray-400 border-gray-700',
}

const STATUS_CLASSES: Record<AlertStatus, string> = {
  open:         'bg-red-950 text-red-400 border-red-800',
  acknowledged: 'bg-yellow-950 text-yellow-400 border-yellow-800',
  closed:       'bg-green-950 text-green-400 border-green-800',
}

export function SeverityBadge({ value }: { value: Severity }) {
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded border font-medium', SEVERITY_CLASSES[value])}>
      {value}
    </span>
  )
}

export function StatusBadge({ value }: { value: AlertStatus }) {
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded border font-medium', STATUS_CLASSES[value])}>
      {value}
    </span>
  )
}

export function TagBadge({ value }: { value: string }) {
  return (
    <span className="text-xs px-1.5 py-0.5 rounded bg-brand-900/40 text-brand-300 border border-brand-800/50 font-mono">
      {value}
    </span>
  )
}
