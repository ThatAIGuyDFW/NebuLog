import { useParams, Link } from 'react-router-dom'
import { useEvent } from '../api/hooks'
import { Spinner } from '../components/Spinner'
import { ErrorMessage } from '../components/ErrorMessage'
import { TagBadge } from '../components/Badge'
import { format } from 'date-fns'

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  if (!value && value !== 0) return null
  return (
    <div className="grid grid-cols-3 gap-2 py-2 border-t border-gray-800">
      <dt className="text-xs text-gray-500 pt-0.5">{label}</dt>
      <dd className="col-span-2 text-sm text-gray-200 font-mono break-all">{value}</dd>
    </div>
  )
}

export function EventDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: event, isLoading, error } = useEvent(id ?? '')

  if (isLoading) return <div className="flex justify-center p-16"><Spinner size="lg" /></div>
  if (error) return <div className="p-6"><ErrorMessage error={error} /></div>
  if (!event) return null

  return (
    <div className="p-6 max-w-4xl space-y-4">
      <div className="flex items-center gap-3">
        <Link to="/events" className="text-brand-400 hover:text-brand-300 text-sm">← Events</Link>
        <h1 className="text-xl font-semibold text-gray-100">Event Detail</h1>
      </div>

      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-2">Core Fields</h2>
        <dl>
          <Row label="ID" value={event.id} />
          <Row label="Received at" value={format(new Date(event.received_at), 'yyyy-MM-dd HH:mm:ss.SSS')} />
          {event.event_time && <Row label="Event time" value={format(new Date(event.event_time), 'yyyy-MM-dd HH:mm:ss')} />}
          <Row label="Source host" value={event.source_host} />
          <Row label="Source type" value={event.source_type} />
          <Row label="Log level" value={event.log_level} />
          <Row label="Category" value={event.category} />
          <Row label="Action" value={event.action} />
        </dl>
      </div>

      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-2">Network</h2>
        <dl>
          <Row label="Src IP" value={event.src_ip} />
          <Row label="Src port" value={event.src_port} />
          <Row label="Dst IP" value={event.dst_ip} />
          <Row label="Dst port" value={event.dst_port} />
          <Row label="Protocol" value={event.protocol} />
          <Row label="Geo" value={[event.geo_city, event.geo_country].filter(Boolean).join(', ')} />
        </dl>
      </div>

      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-2">Identity</h2>
        <dl>
          <Row label="User" value={event.user_name} />
          <Row label="Process" value={event.process_name} />
          <Row label="Event ID" value={event.event_id} />
        </dl>
      </div>

      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-2">Message</h2>
        <p className="text-sm text-gray-200 whitespace-pre-wrap">{event.message}</p>
        {event.raw_message && (
          <>
            <h2 className="text-sm font-semibold text-gray-300 mt-3 mb-1">Raw Message</h2>
            <pre className="text-xs text-gray-400 whitespace-pre-wrap font-mono bg-gray-800 rounded p-3 overflow-auto max-h-48">
              {event.raw_message}
            </pre>
          </>
        )}
        {event.raw_hash && <Row label="SHA-256" value={event.raw_hash} />}
      </div>

      {event.tags && event.tags.length > 0 && (
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-2">Tags</h2>
          <div className="flex flex-wrap gap-2">
            {event.tags.map((t) => <TagBadge key={t} value={t} />)}
          </div>
        </div>
      )}

      {event.extra && Object.keys(event.extra).length > 0 && (
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-2">Extra Fields</h2>
          <pre className="text-xs text-gray-400 whitespace-pre-wrap font-mono overflow-auto max-h-64">
            {JSON.stringify(event.extra, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
