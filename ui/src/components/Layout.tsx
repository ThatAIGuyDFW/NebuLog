import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import clsx from 'clsx'

const NAV = [
  { to: '/',           label: 'Dashboard',  icon: '⬡' },
  { to: '/events',     label: 'Events',     icon: '☰' },
  { to: '/alerts',     label: 'Alerts',     icon: '⚠' },
  { to: '/rules',      label: 'Rules',      icon: '⚙' },
  { to: '/sources',    label: 'Sources',    icon: '⊕' },
  { to: '/compliance', label: 'Compliance', icon: '✓' },
]

export function Layout() {
  const { user, logout } = useAuth()

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="px-5 py-4 border-b border-gray-800">
          <span className="text-brand-400 font-bold text-lg tracking-tight">Sentinel</span>
          <span className="ml-2 text-xs text-gray-500">SIEM</span>
        </div>
        <nav className="flex-1 py-3 space-y-0.5 px-2">
          {NAV.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                  isActive
                    ? 'bg-brand-600/20 text-brand-300 font-medium'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
                )
              }
            >
              <span className="w-4 text-center opacity-70">{icon}</span>
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-gray-800 text-xs text-gray-500">
          <div className="truncate">{user?.name}</div>
          <button onClick={logout} className="mt-1 text-gray-600 hover:text-gray-400">
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto bg-gray-950">
        <Outlet />
      </main>
    </div>
  )
}
