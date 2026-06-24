import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAlerts } from '../api/hooks'
import type { AlertFilters, AlertStatus, Severity } from '../api/types'
import { SeverityBadge, StatusBadge } from '../components/Badge'
import { Spinner } from '../components/Spinner'
import { ErrorMessage } from '../components/ErrorMessage'
import { Pagination } from '../components/Pagination'
import { format } from 'date-fns'

const PAGE_SIZE = 25

export function Alerts() {
  const [filters, setFilters] = useState<AlertFilters>({ page: 1, page_size: PAGE_SIZE })
  const { data, isLoading, error, isFetching } = useAlerts(filters)

  const set = (patch: Partial<AlertFilters>) =>
    setFilters((f) => ({ ...f, ...patch, page: 1 }))

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold text-gray-100">Alerts</h1>

      {/* Filters */}
      <div className="card flex flex-wrap gap-3">
        <div>
          <label className="label">Status</label>
          <select className="select w-36" onChange={(e) => set({ status: (e.target.value as AlertStatus) || undefined })}>
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="closed">Closed</option>
          </select>
        </div>
        <div>
          <label className="label">Severity</label>
          <select className="select w-36" onChange={(e) => set({ severity: (e.target.value as Severity) || undefined })}>
            <option value="">All</option>
            {['critical','high','medium','low','info'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label">Src IP</label>
          <input
            className="input w-40"
            placeholder="filter…"
            onBlur={(e) => set({ src_ip: e.target.value || undefined })}
          />
        </div>
      </div>

      {error && <ErrorMessage error={error} />}

      <div className="card p-0 overflow-auto">
        {(isLoading || isFetching) && (
          <div className="flex justify-center py-2 border-b border-gray-800">
            <Spinner size="sm" />
          </div>
        )}
        <table className="w-full">
          <thead>
            <tr>
              {['Time','Severity','Status','Title','Src IP','Events','Rule'].map((h) => (
                <th key={h} className="table-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data?.items.map((a) => (
              <tr key={a.id} className="hover:bg-gray-800/30">
                <td className="table-td font-mono text-xs text-gray-400 whitespace-nowrap">
                  {format(new Date(a.first_seen), 'MM-dd HH:mm')}
                </td>
                <td className="table-td"><SeverityBadge value={a.severity} /></td>
                <td className="table-td"><StatusBadge value={a.status} /></td>
                <td className="table-td">
                  <Link to={`/alerts/${a.id}`} className="text-brand-400 hover:text-brand-300 text-sm">
                    {a.title}
                  </Link>
                </td>
                <td className="table-td font-mono text-xs">{a.src_ip ?? '—'}</td>
                <td className="table-td text-xs text-right">{a.event_count}</td>
                <td className="table-td text-xs text-gray-400">{a.rule_name ?? '—'}</td>
              </tr>
            ))}
            {!isLoading && (data?.items.length ?? 0) === 0 && (
              <tr>
                <td colSpan={7} className="table-td text-center text-gray-500 py-8">
                  No alerts found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <Pagination
        page={filters.page ?? 1}
        pageSize={PAGE_SIZE}
        total={data?.total ?? 0}
        onChange={(p) => setFilters((f) => ({ ...f, page: p }))}
      />
    </div>
  )
}
