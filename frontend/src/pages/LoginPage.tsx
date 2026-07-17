import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '../services/api'
import { authStore } from '../store/auth'
import { Button, Input } from '../components/common'

export default function LoginPage() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [regForm, setRegForm] = useState({ username: '', email: '', password: '', full_name: '' })

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await authApi.login(form.username, form.password)
      authStore.setAuth(res.data.user, res.data.access_token, res.data.refresh_token)
      navigate('/dashboard')
    } catch (err: any) {
      const detail = err.response?.data?.detail
      setError(Array.isArray(detail) ? detail.map((d: any) => d.msg).join(', ') : detail || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await authApi.register({ ...regForm, role: 'analyst' })
      authStore.setAuth(res.data.user, res.data.access_token, res.data.refresh_token)
      navigate('/dashboard')
    } catch (err: any) {
      const detail = err.response?.data?.detail
      setError(Array.isArray(detail) ? detail.map((d: any) => d.msg).join(', ') : detail || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      {/* Background grid */}
      <div className="fixed inset-0 opacity-5"
        style={{ backgroundImage: 'linear-gradient(rgba(59,130,246,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.3) 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

      <div className="relative w-full max-w-md px-4">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-600/20 border border-blue-500/30 mb-4">
            <span className="text-3xl">🛡️</span>
          </div>
          <h1 className="text-2xl font-bold text-white">ThreatShield AI</h1>
          <p className="text-slate-400 text-sm mt-1">Email Threat Detection Platform</p>
        </div>

        <div className="glass rounded-2xl p-8">
          {/* Tabs */}
          <div className="flex gap-1 mb-6 p-1 bg-slate-800 rounded-lg">
            {(['login', 'register'] as const).map((m) => (
              <button key={m} onClick={() => { setMode(m); setError('') }}
                className={`flex-1 py-2 text-sm font-medium rounded-md transition-all capitalize ${mode === m ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
                {m}
              </button>
            ))}
          </div>

          {mode === 'login' ? (
            <form onSubmit={handleLogin} className="flex flex-col gap-4">
              <Input label="Username" value={form.username} onChange={e => setForm(p => ({ ...p, username: e.target.value }))}
                placeholder="your_username" required />
              <Input label="Password" type="password" value={form.password} onChange={e => setForm(p => ({ ...p, password: e.target.value }))}
                placeholder="••••••••" required />
              {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">{error}</p>}
              <Button type="submit" loading={loading} className="w-full mt-2">Sign In</Button>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="flex flex-col gap-4">
              <Input label="Full Name" value={regForm.full_name} onChange={e => setRegForm(p => ({ ...p, full_name: e.target.value }))} placeholder="John Doe" />
              <Input label="Username" value={regForm.username} onChange={e => setRegForm(p => ({ ...p, username: e.target.value }))} placeholder="john_doe" required />
              <Input label="Email" type="email" value={regForm.email} onChange={e => setRegForm(p => ({ ...p, email: e.target.value }))} placeholder="john@example.com" required />
              <Input label="Password" type="password" value={regForm.password} onChange={e => setRegForm(p => ({ ...p, password: e.target.value }))} placeholder="Min 6 characters" required />
              {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">{error}</p>}
              <Button type="submit" loading={loading} className="w-full mt-2">Create Account</Button>
            </form>
          )}
        </div>

        <p className="text-center text-slate-600 text-xs mt-6">
          ThreatShield AI · Powered by NLP threat intelligence
        </p>
      </div>
    </div>
  )
}