import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useAlert, usePatchAlert } from '../api/hooks'
import { useAuth } from '../auth/AuthContext'
import type { AlertStatus } from '../api/types'
import { SeverityBadge, StatusBadge } from '../components/Badge'
import { Spinner } from '../components/Spinner'
import { ErrorMessage } from '../components/ErrorMessage'
import { format } from 'date-fns'

export function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: alert, isLoading, error } = useAlert(id ?? '')
  const patch = usePatchAlert(id ?? '')
  const { hasRole } = useAuth()
  const canEdit = hasRole('Sentinel.Admin', 'Sentinel.Analyst')

  const [status, setStatus] = useState<AlertStatus | ''>('')
  const [assignee, setAssignee] = useState('')

  if (isLoading) return <div className="flex justify-center p-16"><Spinner size="lg" /></div>
  if (error) return <div className="p-6"><ErrorMessage error={error} /></div>
  if (!alert) return null

  const handlePatch = () => {
    const body: Record<string, string> = {}
    if (status) body.status = status
    if (assignee.trim()) body.assigned_to = assignee.trim()
    if (Object.keys(body).length === 0) return
    patch.mutate(body as { status?: AlertStatus; assigned_to?: string })
  }

  return (
    <div className="p-6 max-w-4xl space-y-4">
      <div className="flex items-center gap-3">
        <Link to="/alerts" className="text-brand-400 hover:text-brand-300 text-sm">← Alerts</Link>
        <h1 className="text-xl font-semibold text-gray-100">{alert.title}</h1>
      </div>

      {/* Status bar */}
      <div className="card flex flex-wrap items-center gap-4">
        <SeverityBadge value={alert.severity} />
        <StatusBadge value={alert.status} />
        <span className="text-xs text-gray-400">
          First: {format(new Date(alert.first_seen), 'yyyy-MM-dd HH:mm')}
        </span>
        <span className="text-xs text-gray-400">
          Last: {format(new Date(alert.last_seen), 'yyyy-MM-dd HH:mm')}
        </span>
        <span className="text-xs text-gray-400">{alert.event_count} events</span>
        {alert.assigned_to && (
          <span className="text-xs text-gray-400">Assigned: {alert.assigned_to}</span>
        )}
      </div>

      {/* Description */}
      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-1">Description</h2>
        <p className="text-sm text-gray-300">{alert.description ?? 'No description'}</p>
        {alert.src_ip && (
          <p className="mt-2 text-xs text-gray-400">
            Source IP: <span className="font-mono text-gray-200">{alert.src_ip}</span>
          </p>
        )}
        {alert.rule_name && (
          <p className="text-xs text-gray-400">
            Rule: <span className="text-gray-200">{alert.rule_name}</span>
          </p>
        )}
      </div>

      {/* Update form (Analyst+) */}
      {canEdit && (
        <div className="card space-y-3">
          <h2 className="text-sm font-semibold text-gray-300">Update Alert</h2>
          <div className="flex flex-wrap gap-3">
            <div>
              <label className="label">Status</label>
              <select className="select w-40" value={status} onChange={(e) => setStatus(e.target.value as AlertStatus)}>
                <option value="">— keep current —</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="closed">Closed</option>
              </select>
            </div>
            <div>
              <label className="label">Assign to</label>
              <input
                className="input w-48"
                placeholder="email or name"
                value={assignee}
                onChange={(e) => setAssignee(e.target.value)}
              />
            </div>
            <div className="flex items-end">
              <button
                className="btn-primary"
                onClick={handlePatch}
                disabled={patch.isPending}
              >
                {patch.isPending ? <Spinner size="sm" /> : 'Save'}
              </button>
            </div>
          </div>
          {patch.isError && <ErrorMessage error={patch.error} />}
          {patch.isSuccess && (
            <p className="text-green-400 text-sm">Alert updated.</p>
          )}
        </div>
      )}

      {/* Linked events */}
      {alert.linked_events.length > 0 && (
        <div className="card p-0">
          <h2 className="text-sm font-semibold text-gray-300 px-4 py-3 border-b border-gray-800">
            Linked Events ({alert.linked_events.length})
          </h2>
          <table className="w-full">
            <thead>
              <tr>
                {['Time','Source','Level','Category','Src IP','Message'].map((h) => (
                  <th key={h} className="table-th">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alert.linked_events.map((e) => (
                <tr key={e.id} className="hover:bg-gray-800/30">
                  <td className="table-td font-mono text-xs text-gray-400 whitespace-nowrap">
                    {format(new Date(e.received_at), 'MM-dd HH:mm:ss')}
                  </td>
                  <td className="table-td text-xs font-mono">{e.source_host}</td>
                  <td className="table-td text-xs">{e.log_level ?? '—'}</td>
                  <td className="table-td text-xs">{e.category ?? '—'}</td>
                  <td className="table-td text-xs font-mono">{e.src_ip ?? '—'}</td>
                  <td className="table-td text-xs text-gray-300 truncate max-w-xs">{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
