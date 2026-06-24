export function Spinner({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const sz = { sm: 'h-4 w-4', md: 'h-6 w-6', lg: 'h-10 w-10' }[size]
  return (
    <span
      className={`inline-block ${sz} animate-spin rounded-full border-2 border-gray-600 border-t-brand-500`}
      role="status"
      aria-label="Loading"
    />
  )
}
