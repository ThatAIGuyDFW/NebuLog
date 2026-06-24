import { useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid, PieChart, Pie, Cell,
} from 'recharts'
import { useDashboardSummary, useDashboardTimeline } from '../api/hooks'
import { Spinner } from '../components/Spinner'
import { ErrorMessage } from '../components/ErrorMessage'
import type { Severity } from '../api/types'
import { format } from 'date-fns'

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#f87171',
  high:     '#fb923c',
  medium:   '#facc15',
  low:      '#60a5fa',
  info:     '#94a3b8',
}

const CATEGORY_COLORS = ['#6366f1', '#8b5cf6', '#ec4899', '#14b8a6', '#f59e0b', '#10b981']

type Bucket = '1m' | '5m' | '1h'

function StatCard({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="card flex flex-col gap-1">
      <span className="text-xs text-gray-500">{label}</span>
      <span className="text-2xl font-bold text-gray-100">{value}</span>
    </div>
  )
}

export function Dashboard() {
  const [bucket, setBucket] = useState<Bucket>('5m')
  const { data: summary, isLoading, error } = useDashboardSummary()
  const { data: timeline } = useDashboardTimeline(bucket)

  if (isLoading) return <div className="flex justify-center p-16"><Spinner size="lg" /></div>
  if (error) return <div className="p-6"><ErrorMessage error={error} /></div>
  if (!summary) return null

  const timelineFormatted = timeline?.map((t) => ({
    ...t,
    time: format(new Date(t.bucket), bucket === '1m' ? 'HH:mm' : bucket === '5m' ? 'HH:mm' : 'HH:00'),
  })) ?? []

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold text-gray-100">Dashboard</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Events (24h)" value={summary.total_events_24h.toLocaleString()} />
        <StatCard label="Open Alerts" value={summary.open_alerts} />
        <StatCard label="Active Sources" value={summary.active_sources} />
        <StatCard
          label="Critical Alerts"
          value={summary.events_by_severity.find((s) => s.severity === 'critical')?.count ?? 0}
        />
      </div>

      {/* Timeline */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-300">Event Volume</h2>
          <div className="flex gap-1">
            {(['1m', '5m', '1h'] as Bucket[]).map((b) => (
              <button
                key={b}
                onClick={() => setBucket(b)}
                className={`px-2 py-1 rounded text-xs ${bucket === b ? 'bg-brand-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
              >
                {b}
              </button>
            ))}
          </div>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={timelineFormatted}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 11 }} />
            <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
            <Tooltip
              contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: 6 }}
              labelStyle={{ color: '#e5e7eb' }}
            />
            <Line type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Events by severity */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Events by Severity</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={summary.events_by_severity} layout="vertical">
              <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <YAxis dataKey="severity" type="category" tick={{ fill: '#9ca3af', fontSize: 11 }} width={60} />
              <Tooltip
                contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: 6 }}
              />
              <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                {summary.events_by_severity.map((entry) => (
                  <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity as Severity]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Events by category */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Events by Category</h2>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={summary.events_by_category}
                dataKey="count"
                nameKey="category"
                cx="50%"
                cy="50%"
                outerRadius={70}
                label={({ category, percent }) =>
                  percent > 0.05 ? `${category} ${(percent * 100).toFixed(0)}%` : ''
                }
                labelLine={false}
              >
                {summary.events_by_category.map((_, i) => (
                  <Cell key={i} fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: 6 }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Top sources */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Top Sources</h2>
          <div className="space-y-2">
            {summary.top_sources.map((s) => (
              <div key={s.source_host} className="flex items-center gap-2">
                <span className="text-xs text-gray-300 flex-1 truncate font-mono">{s.source_host}</span>
                <span className="text-xs text-gray-500">{s.event_count.toLocaleString()}</span>
                <div
                  className="h-1.5 rounded bg-brand-600"
                  style={{
                    width: `${(s.event_count / (summary.top_sources[0]?.event_count || 1)) * 64}px`,
                  }}
                />
              </div>
            ))}
          </div>
          <h2 className="text-sm font-semibold text-gray-300 mt-4 mb-3">Top Rules</h2>
          <div className="space-y-1.5">
            {summary.top_rules.map((r) => (
              <div key={r.rule_name} className="flex justify-between text-xs">
                <span className="text-gray-300 truncate">{r.rule_name}</span>
                <span className="text-gray-500 ml-2">{r.alert_count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
