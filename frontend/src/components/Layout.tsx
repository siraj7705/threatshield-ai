// LOCATION: threatshield-ai/frontend/src/components/Layout.tsx
import React, { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { authStore } from '../store/auth'
import { clsx } from '../utils'

const NAV_ITEMS = [
  { to: '/dashboard', icon: '📊', label: 'Dashboard', roles: ['admin', 'analyst', 'investigator'] },
  { to: '/emails', icon: '📧', label: 'Emails', roles: ['admin', 'analyst', 'investigator'] },
  { to: '/alerts', icon: '🔔', label: 'Alerts', roles: ['admin', 'analyst', 'investigator'] },
  { to: '/cases', icon: '📁', label: 'Cases', roles: ['admin', 'analyst', 'investigator'] },
  { to: '/search', icon: '🔍', label: 'Search', roles: ['admin', 'analyst', 'investigator'] },
  { to: '/graph', icon: '🕸️', label: 'Graph Analysis', roles: ['admin', 'analyst', 'investigator'] },
  { to: '/gmail', icon: '📬', label: 'Gmail Watch', roles: ['admin', 'analyst'] },
  { to: '/settings', icon: '⚙️', label: 'Settings', roles: ['admin', 'analyst', 'investigator'] },
  { to: '/trusted-senders', icon: '⭐', label: 'Trusted Senders', roles: ['admin', 'analyst'] },
  { to: '/users', icon: '👥', label: 'Users', roles: ['admin'] },
]

const ROLE_BADGE: Record<string, string> = {
  admin: 'bg-red-500/20 text-red-400',
  analyst: 'bg-blue-500/20 text-blue-400',
  investigator: 'bg-purple-500/20 text-purple-400',
}

export default function Layout() {
  const navigate = useNavigate()
  const user = authStore.getUser()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const userRole = user?.role || 'analyst'

  const logout = () => {
    authStore.logout()
    navigate('/login')
  }

  const visibleNavItems = NAV_ITEMS.filter(item => item.roles.includes(userRole))

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      {/* Sidebar */}
      <aside className={clsx(
        'flex flex-col bg-slate-900 border-r border-slate-800 transition-all duration-300',
        sidebarOpen ? 'w-56' : 'w-16'
      )}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-5 border-b border-slate-800">
          <div className="w-8 h-8 flex-shrink-0 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-lg">🛡️</div>
          {sidebarOpen && <span className="font-bold text-white text-sm">ThreatShield</span>}
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 px-2 overflow-y-auto">
          {visibleNavItems.map(({ to, icon, label }) => (
            <NavLink key={to} to={to}
              className={({ isActive }) => clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg mb-1 text-sm transition-all',
                isActive
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/20'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
              )}>
              <span className="text-base flex-shrink-0">{icon}</span>
              {sidebarOpen && <span className="font-medium">{label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* User + Collapse */}
        <div className="border-t border-slate-800 p-3">
          {sidebarOpen && user && (
            <div className="flex items-center gap-2 mb-3 px-2">
              <div className="w-7 h-7 rounded-full bg-blue-600/30 border border-blue-500/30 flex items-center justify-center text-xs font-bold text-blue-400">
                {user.username[0].toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-slate-200 truncate">{user.username}</p>
                <span className={`text-xs px-1.5 py-0.5 rounded font-medium capitalize ${ROLE_BADGE[userRole] || 'text-slate-400'}`}>
                  {userRole}
                </span>
              </div>
            </div>
          )}
          <button onClick={logout}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-400 hover:text-red-400 rounded-lg hover:bg-red-500/10 transition-all">
            <span>🚪</span>
            {sidebarOpen && <span>Logout</span>}
          </button>
          <button onClick={() => setSidebarOpen(p => !p)}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-500 hover:text-slate-300 rounded-lg hover:bg-slate-800 transition-all mt-1">
            <span>{sidebarOpen ? '◀' : '▶'}</span>
            {sidebarOpen && <span>Collapse</span>}
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}