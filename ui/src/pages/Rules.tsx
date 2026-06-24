import { useState } from 'react'
import { useRules, useCreateRule, useUpdateRule, useDeleteRule } from '../api/hooks'
import { useAuth } from '../auth/AuthContext'
import type { RuleSummary, RuleCreate, RuleType, Severity } from '../api/types'
import { SeverityBadge } from '../components/Badge'
import { Spinner } from '../components/Spinner'
import { ErrorMessage } from '../components/ErrorMessage'
import { format } from 'date-fns'

const EMPTY_RULE: RuleCreate = {
  name: '',
  rule_type: 'threshold',
  severity: 'medium',
  body: { filters: {}, count: 5, window_seconds: 600 },
}

function RuleForm({
  initial,
  onSave,
  onCancel,
  isPending,
  error,
}: {
  initial: RuleCreate
  onSave: (r: RuleCreate) => void
  onCancel: () => void
  isPending: boolean
  error: Error | null
}) {
  const [form, setForm] = useState(initial)
  const [bodyText, setBodyText] = useState(JSON.stringify(initial.body, null, 2))
  const [bodyError, setBodyError] = useState('')

  const handleSave = () => {
    try {
      const body = JSON.parse(bodyText)
      setBodyError('')
      onSave({ ...form, body })
    } catch {
      setBodyError('Invalid JSON')
    }
  }

  return (
    <div className="card space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="md:col-span-2">
          <label className="label">Name *</label>
          <input
            className="input"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          />
        </div>
        <div>
          <label className="label">Rule type</label>
          <select
            className="select"
            value={form.rule_type}
            onChange={(e) => setForm((f) => ({ ...f, rule_type: e.target.value as RuleType }))}
          >
            {['threshold','sequence','absence','blacklist','anomaly'].map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label">Severity</label>
          <select
            className="select"
            value={form.severity}
            onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value as Severity }))}
          >
            {['critical','high','medium','low','info'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div className="md:col-span-2">
          <label className="label">Description</label>
          <input
            className="input"
            value={form.description ?? ''}
            onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
          />
        </div>
      </div>
      <div>
        <label className="label">Body (JSON)</label>
        <textarea
          className="input font-mono text-xs h-48 resize-y"
          value={bodyText}
          onChange={(e) => setBodyText(e.target.value)}
        />
        {bodyError && <p className="text-red-400 text-xs mt-1">{bodyError}</p>}
      </div>
      {error && <ErrorMessage error={error} />}
      <div className="flex gap-2">
        <button className="btn-primary" onClick={handleSave} disabled={isPending || !form.name}>
          {isPending ? <Spinner size="sm" /> : 'Save'}
        </button>
        <button className="btn-ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  )
}

export function Rules() {
  const { data, isLoading, error } = useRules()
  const createRule = useCreateRule()
  const deleteRule = useDeleteRule()
  const { hasRole } = useAuth()
  const isAdmin = hasRole('Sentinel.Admin')

  const [editing, setEditing] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  if (isLoading) return <div className="flex justify-center p-16"><Spinner size="lg" /></div>
  if (error) return <div className="p-6"><ErrorMessage error={error} /></div>

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-100">Correlation Rules</h1>
        {isAdmin && !creating && (
          <button className="btn-primary" onClick={() => setCreating(true)}>+ New Rule</button>
        )}
      </div>

      {creating && (
        <RuleForm
          initial={EMPTY_RULE}
          onSave={(r) => createRule.mutate(r, { onSuccess: () => setCreating(false) })}
          onCancel={() => setCreating(false)}
          isPending={createRule.isPending}
          error={createRule.error}
        />
      )}

      <div className="card p-0 overflow-auto">
        <table className="w-full">
          <thead>
            <tr>
              {['Name','Type','Severity','Enabled','Created'].concat(isAdmin ? ['Actions'] : []).map((h) => (
                <th key={h} className="table-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data?.items.map((r) => (
              editing === r.id
                ? <EditRow key={r.id} rule={r} onDone={() => setEditing(null)} />
                : (
                  <tr key={r.id} className="hover:bg-gray-800/30">
                    <td className="table-td font-medium">{r.name}</td>
                    <td className="table-td text-xs text-gray-400">{r.rule_type}</td>
                    <td className="table-td"><SeverityBadge value={r.severity} /></td>
                    <td className="table-td">
                      <span className={r.enabled ? 'text-green-400 text-xs' : 'text-gray-600 text-xs'}>
                        {r.enabled ? '● On' : '○ Off'}
                      </span>
                    </td>
                    <td className="table-td text-xs text-gray-400">
                      {format(new Date(r.created_at), 'yyyy-MM-dd')}
                    </td>
                    {isAdmin && (
                      <td className="table-td">
                        <div className="flex gap-2">
                          <button
                            className="text-xs text-brand-400 hover:text-brand-300"
                            onClick={() => setEditing(r.id)}
                          >
                            Edit
                          </button>
                          <button
                            className="text-xs text-red-400 hover:text-red-300"
                            onClick={() => {
                              if (confirm(`Delete rule "${r.name}"?`)) deleteRule.mutate(r.id)
                            }}
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                )
            ))}
            {(data?.items.length ?? 0) === 0 && (
              <tr>
                <td colSpan={6} className="table-td text-center text-gray-500 py-8">No rules</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function EditRow({ rule, onDone }: { rule: RuleSummary; onDone: () => void }) {
  const update = useUpdateRule(rule.id)
  return (
    <tr>
      <td colSpan={6} className="px-0 py-0">
        <RuleForm
          initial={{ name: rule.name, rule_type: rule.rule_type, severity: rule.severity, body: {} }}
          onSave={(r) => update.mutate(r, { onSuccess: onDone })}
          onCancel={onDone}
          isPending={update.isPending}
          error={update.error}
        />
      </td>
    </tr>
  )
}
