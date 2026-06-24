import { useState } from 'react'
import { useComplianceReport } from '../api/hooks'
import { Spinner } from '../components/Spinner'
import { ErrorMessage } from '../components/ErrorMessage'
import { format } from 'date-fns'

function Metric({ label, value, ok }: { label: string; value: React.ReactNode; ok?: boolean }) {
  return (
    <div className="card flex justify-between items-center">
      <span className="text-sm text-gray-300">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-sm font-semibold text-gray-100">{value}</span>
        {ok !== undefined && (
          <span className={ok ? 'text-green-400 text-xs' : 'text-red-400 text-xs'}>
            {ok ? '✓ OK' : '✗ FAIL'}
          </span>
        )}
      </div>
    </div>
  )
}

export function Compliance() {
  const [framework, setFramework] = useState<'hipaa' | 'pci_dss'>('hipaa')
  const { data, isLoading, error } = useComplianceReport(framework)

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-4">
        <h1 className="text-xl font-semibold text-gray-100">Compliance Report</h1>
        <div className="flex gap-1">
          {(['hipaa', 'pci_dss'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFramework(f)}
              className={`px-3 py-1 rounded text-sm ${framework === f ? 'bg-brand-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              {f.toUpperCase().replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {isLoading && <div className="flex justify-center p-16"><Spinner size="lg" /></div>}
      {error && <ErrorMessage error={error} />}

      {data && (
        <>
          <p className="text-xs text-gray-500">
            Generated: {format(new Date(data.generated_at), 'yyyy-MM-dd HH:mm:ss')} UTC
          </p>

          <div className="space-y-2">
            <Metric label="Failed Logins (24h)" value={data.failed_logins_24h} />
            <Metric label="Privilege Escalations (24h)" value={data.privilege_escalations_24h} />
            <Metric label="Audit Log Clears (24h)" value={data.audit_log_clears_24h} ok={data.audit_log_clears_24h === 0} />
            {data.cardholder_env_events_24h !== undefined && (
              <Metric label="Cardholder Env Events (24h)" value={data.cardholder_env_events_24h} />
            )}
            {data.daily_review_gaps !== undefined && (
              <Metric label="Daily Review Gaps" value={data.daily_review_gaps} ok={data.daily_review_gaps === 0} />
            )}
          </div>

          {/* Retention posture */}
          <div className="card space-y-2">
            <h2 className="text-sm font-semibold text-gray-300">Log Retention</h2>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <span className="text-gray-400">Retention span</span>
              <span className="text-gray-100">{data.retention.retention_days} days</span>

              <span className="text-gray-400">Total events</span>
              <span className="text-gray-100">{data.retention.total_events.toLocaleString()}</span>

              <span className="text-gray-400">Oldest event</span>
              <span className="text-gray-100 font-mono text-xs">
                {data.retention.oldest_event
                  ? format(new Date(data.retention.oldest_event), 'yyyy-MM-dd')
                  : 'No events'}
              </span>

              <span className="text-gray-400">HIPAA (6yr / 2192d)</span>
              <span className={data.retention.meets_hipaa ? 'text-green-400' : 'text-red-400'}>
                {data.retention.meets_hipaa ? '✓ Met' : '✗ Not met'}
              </span>

              <span className="text-gray-400">PCI DSS (12mo hot)</span>
              <span className={data.retention.meets_pci ? 'text-green-400' : 'text-red-400'}>
                {data.retention.meets_pci ? '✓ Met' : '✗ Not met'}
              </span>
            </div>
          </div>

          {/* Log gaps */}
          {data.log_gaps.length > 0 ? (
            <div className="card p-0">
              <h2 className="text-sm font-semibold text-gray-300 px-4 py-3 border-b border-gray-800">
                Log Gaps ({data.log_gaps.length})
              </h2>
              <table className="w-full">
                <thead>
                  <tr>
                    {['Source','Gap Start','Gap End','Duration'].map((h) => (
                      <th key={h} className="table-th">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.log_gaps.map((g, i) => (
                    <tr key={i} className="hover:bg-gray-800/30">
                      <td className="table-td font-mono text-xs">{g.source_host}</td>
                      <td className="table-td text-xs">
                        {format(new Date(g.gap_start), 'yyyy-MM-dd HH:mm')}
                      </td>
                      <td className="table-td text-xs">
                        {format(new Date(g.gap_end), 'yyyy-MM-dd HH:mm')}
                      </td>
                      <td className="table-td text-xs text-red-400">{g.gap_minutes} min</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="card text-sm text-green-400">✓ No log gaps detected</div>
          )}
        </>
      )}
    </div>
  )
}
