export function ErrorMessage({ error }: { error: unknown }) {
  const msg =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : 'An unexpected error occurred'
  return (
    <div className="rounded-md bg-red-950 border border-red-800 text-red-300 text-sm px-4 py-3">
      {msg}
    </div>
  )
}
