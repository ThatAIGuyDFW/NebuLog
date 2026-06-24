import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { useEvents } from '../api/hooks'
import type { EventSummary, EventFilters, Category, LogLevel, SourceType } from '../api/types'
import { Spinner } from '../components/Spinner'
import { ErrorMessage } from '../components/ErrorMessage'
import { Pagination } from '../components/Pagination'
import { format } from 'date-fns'

const col = createColumnHelper<EventSummary>()

const columns = [
  col.accessor('received_at', {
    header: 'Time',
    cell: (i) => (
      <span className="font-mono text-xs text-gray-400">
        {format(new Date(i.getValue()), 'MM-dd HH:mm:ss')}
      </span>
    ),
  }),
  col.accessor('source_host', {
    header: 'Source',
    cell: (i) => <span className="font-mono text-xs">{i.getValue()}</span>,
  }),
  col.accessor('source_type', {
    header: 'Type',
    cell: (i) => <span className="text-xs text-gray-400">{i.getValue() ?? '—'}</span>,
  }),
  col.accessor('log_level', {
    header: 'Level',
    cell: (i) => {
      const v = i.getValue()
      if (!v) return <span className="text-gray-600">—</span>
      const colors: Record<string, string> = {
        emergency: 'text-red-400', alert: 'text-red-400', critical: 'text-red-400',
        error: 'text-orange-400', warning: 'text-yellow-400',
        notice: 'text-blue-400', info: 'text-gray-300', debug: 'text-gray-500',
      }
      return <span className={`text-xs font-medium ${colors[v] ?? 'text-gray-400'}`}>{v}</span>
    },
  }),
  col.accessor('category', {
    header: 'Category',
    cell: (i) => <span className="text-xs text-gray-400">{i.getValue() ?? '—'}</span>,
  }),
  col.accessor('src_ip', {
    header: 'Src IP',
    cell: (i) => <span className="font-mono text-xs text-gray-300">{i.getValue() ?? '—'}</span>,
  }),
  col.accessor('user_name', {
    header: 'User',
    cell: (i) => <span className="text-xs">{i.getValue() ?? '—'}</span>,
  }),
  col.accessor('message', {
    header: 'Message',
    cell: (i) => (
      <span className="text-xs text-gray-300 truncate block max-w-xs">{i.getValue()}</span>
    ),
  }),
  col.display({
    id: 'actions',
    cell: (i) => (
      <Link to={`/events/${i.row.original.id}`} className="text-brand-400 hover:text-brand-300 text-xs">
        Details
      </Link>
    ),
  }),
]

const PAGE_SIZE = 50

export function Events() {
  const [filters, setFilters] = useState<EventFilters>({ page: 1, page_size: PAGE_SIZE, sort_order: 'desc' })
  const { data, isLoading, error, isFetching } = useEvents(filters)

  const table = useReactTable({
    data: data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  const set = (patch: Partial<EventFilters>) =>
    setFilters((f) => ({ ...f, ...patch, page: 1 }))

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold text-gray-100">Events</h1>

      {/* Filter bar */}
      <div className="card grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <div>
          <label className="label">Free search</label>
          <input
            className="input"
            placeholder="keyword…"
            onBlur={(e) => set({ q: e.target.value || undefined })}
            onKeyDown={(e) => e.key === 'Enter' && set({ q: (e.target as HTMLInputElement).value || undefined })}
          />
        </div>
        <div>
          <label className="label">Source IP</label>
          <input
            className="input"
            placeholder="10.0.0.1"
            onBlur={(e) => set({ src_ip: e.target.value || undefined })}
          />
        </div>
        <div>
          <label className="label">Source</label>
          <input
            className="input"
            placeholder="hostname…"
            onBlur={(e) => set({ source: e.target.value || undefined })}
          />
        </div>
        <div>
          <label className="label">Category</label>
          <select className="select" onChange={(e) => set({ category: (e.target.value as Category) || undefined })}>
            <option value="">All</option>
            {['auth','network','endpoint','system','threat','compliance'].map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label">Level</label>
          <select className="select" onChange={(e) => set({ log_level: (e.target.value as LogLevel) || undefined })}>
            <option value="">All</option>
            {['emergency','alert','critical','error','warning','notice','info','debug'].map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label">Type</label>
          <select className="select" onChange={(e) => set({ source_type: (e.target.value as SourceType) || undefined })}>
            <option value="">All</option>
            {['fortigate','cisco_asa','cisco_ios','windows','linux'].map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label">From</label>
          <input type="datetime-local" className="input" onChange={(e) => set({ time_from: e.target.value ? new Date(e.target.value).toISOString() : undefined })} />
        </div>
        <div>
          <label className="label">To</label>
          <input type="datetime-local" className="input" onChange={(e) => set({ time_to: e.target.value ? new Date(e.target.value).toISOString() : undefined })} />
        </div>
        <div>
          <label className="label">User</label>
          <input className="input" placeholder="username…" onBlur={(e) => set({ user: e.target.value || undefined })} />
        </div>
        <div>
          <label className="label">Sort</label>
          <select className="select" onChange={(e) => set({ sort_order: e.target.value as 'asc' | 'desc' })}>
            <option value="desc">Newest first</option>
            <option value="asc">Oldest first</option>
          </select>
        </div>
      </div>

      {error && <ErrorMessage error={error} />}

      <div className="card p-0 overflow-auto">
        {(isLoading || isFetching) && (
          <div className="flex justify-center py-2 border-b border-gray-800">
            <Spinner size="sm" />
          </div>
        )}
        <table className="w-full min-w-max">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th key={h.id} className="table-th whitespace-nowrap">
                    {flexRender(h.column.columnDef.header, h.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} className="hover:bg-gray-800/30">
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="table-td whitespace-nowrap">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
            {!isLoading && table.getRowModel().rows.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="table-td text-center text-gray-500 py-8">
                  No events found
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
