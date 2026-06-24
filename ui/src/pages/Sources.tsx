import { useState } from 'react'
import { useSources, useCreateSource, useToggleSource } from '../api/hooks'
import type { SourceCreate, SourceType } from '../api/types'
import { Spinner } from '../components/Spinner'
import { ErrorMessage } from '../components/ErrorMessage'
import { format } from 'date-fns'

const EMPTY: SourceCreate = { ip_address: '', source_type: 'fortigate' }

export function Sources() {
  const { data, isLoading, error } = useSources()
  const createSource = useCreateSource()
  const toggle = useToggleSource()

  const [form, setForm] = useState<SourceCreate>(EMPTY)
  const [showForm, setShowForm] = useState(false)

  const handleSubmit = () => {
    if (!form.ip_address) return
    createSource.mutate(form, {
      onSuccess: () => {
        setForm(EMPTY)
        setShowForm(false)
      },
    })
  }

  if (isLoading) return <div className="flex justify-center p-16"><Spinner size="lg" /></div>
  if (error) return <div className="p-6"><ErrorMessage error={error} /></div>

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-100">Log Sources</h1>
        {!showForm && (
          <button className="btn-primary" onClick={() => setShowForm(true)}>+ Add Source</button>
        )}
      </div>

      {showForm && (
        <div className="card space-y-3">
          <h2 className="text-sm font-semibold text-gray-300">Register New Source</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div>
              <label className="label">IP Address *</label>
              <input
                className="input"
                placeholder="192.168.1.1"
                value={form.ip_address}
                onChange={(e) => setForm((f) => ({ ...f, ip_address: e.target.value }))}
              />
            </div>
            <div>
              <label className="label">Source type</label>
              <select
                className="select"
                value={form.source_type}
                onChange={(e) => setForm((f) => ({ ...f, source_type: e.target.value as SourceType }))}
              >
                {['fortigate','cisco_asa','cisco_ios','windows','linux'].map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="label">Hostname</label>
              <input
                className="input"
                placeholder="optional"
                value={form.hostname ?? ''}
                onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))}
              />
            </div>
            <div>
              <label className="label">Label</label>
              <input
                className="input"
                placeholder="optional"
                value={form.label ?? ''}
                onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
              />
            </div>
          </div>
          {createSource.error && <ErrorMessage error={createSource.error} />}
          <div className="flex gap-2">
            <button
              className="btn-primary"
              onClick={handleSubmit}
              disabled={createSource.isPending || !form.ip_address}
            >
              {createSource.isPending ? <Spinner size="sm" /> : 'Register'}
            </button>
            <button className="btn-ghost" onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="card p-0 overflow-auto">
        <table className="w-full">
          <thead>
            <tr>
              {['IP Address','Hostname','Type','Label','Status','Rate/min','Last Seen',''].map((h) => (
                <th key={h} className="table-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data?.items.map((s) => (
              <tr key={s.id} className="hover:bg-gray-800/30">
                <td className="table-td font-mono text-sm">{s.ip_address}</td>
                <td className="table-td text-sm text-gray-300">{s.hostname ?? '—'}</td>
                <td className="table-td text-xs text-gray-400">{s.source_type}</td>
                <td className="table-td text-xs text-gray-400">{s.label ?? '—'}</td>
                <td className="table-td">
                  <span className={s.enabled ? 'text-green-400 text-xs' : 'text-gray-600 text-xs'}>
                    {s.enabled ? '● Enabled' : '○ Disabled'}
                  </span>
                </td>
                <td className="table-td text-xs text-right">{s.event_rate_1m}</td>
                <td className="table-td text-xs text-gray-400">
                  {s.last_seen ? format(new Date(s.last_seen), 'MM-dd HH:mm') : '—'}
                </td>
                <td className="table-td">
                  <button
                    className={s.enabled ? 'text-xs text-yellow-400 hover:text-yellow-300' : 'text-xs text-green-400 hover:text-green-300'}
                    onClick={() => toggle.mutate({ id: s.id, enable: !s.enabled })}
                    disabled={toggle.isPending}
                  >
                    {s.enabled ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
            {(data?.items.length ?? 0) === 0 && (
              <tr>
                <td colSpan={8} className="table-td text-center text-gray-500 py-8">
                  No sources registered
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
