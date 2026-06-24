interface Props {
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
}

export function Pagination({ page, pageSize, total, onChange }: Props) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  if (totalPages <= 1) return null

  return (
    <div className="flex items-center justify-between text-sm text-gray-400 mt-3">
      <span>
        {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
      </span>
      <div className="flex gap-1">
        <button
          className="btn-ghost px-2 py-1 text-xs"
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
        >
          ‹ Prev
        </button>
        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
          const p = Math.max(1, Math.min(page - 2, totalPages - 4)) + i
          return (
            <button
              key={p}
              className={`px-2 py-1 rounded text-xs ${p === page ? 'bg-brand-600 text-white' : 'hover:bg-gray-800 text-gray-400'}`}
              onClick={() => onChange(p)}
            >
              {p}
            </button>
          )
        })}
        <button
          className="btn-ghost px-2 py-1 text-xs"
          disabled={page >= totalPages}
          onClick={() => onChange(page + 1)}
        >
          Next ›
        </button>
      </div>
    </div>
  )
}
