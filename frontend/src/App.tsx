// LOCATION: threatshield-ai/frontend/src/App.tsx
import React, { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { authStore } from './store/auth'
import Layout from './components/Layout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import EmailsPage from './pages/EmailsPage'
import AlertsPage from './pages/AlertsPage'
import CasesPage from './pages/CasesPage'
import GmailPage from './pages/GmailPage'
import SettingsPage from './pages/SettingsPage'
import TrustedSendersPage from './pages/TrustedSendersPage'
import UsersPage from './pages/UsersPage'
import SearchPage from './pages/SearchPage'
import GraphPage from './pages/GraphPage'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const [authed, setAuthed] = useState(authStore.isAuthenticated())
  useEffect(() => {
    return authStore.subscribe(() => setAuthed(authStore.isAuthenticated()))
  }, [])
  return authed ? <>{children}</> : <Navigate to="/login" replace />
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const user = authStore.getUser()
  if (!user) return <Navigate to="/login" replace />
  if (user.role !== 'admin') return <Navigate to="/dashboard" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="emails" element={<EmailsPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="cases" element={<CasesPage />} />
          <Route path="gmail" element={<GmailPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="trusted-senders" element={<TrustedSendersPage />} />
          <Route path="graph" element={<GraphPage />} />
          <Route path="search" element={<SearchPage />} />
          {/* Admin only */}
          <Route path="users" element={<AdminRoute><UsersPage /></AdminRoute>} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  )
}