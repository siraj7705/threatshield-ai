import { User } from '../types'

interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  setAuth: (user: User, token: string, refreshToken: string) => void
  logout: () => void
}

// Simple store using localStorage (no zustand dep — use React context instead)
let _listeners: Array<() => void> = []

function notifyListeners() {
  _listeners.forEach((fn) => fn())
}

export const authStore = {
  getUser: (): User | null => {
    const u = localStorage.getItem('user')
    return u ? JSON.parse(u) : null
  },
  getToken: () => localStorage.getItem('access_token'),
  isAuthenticated: () => !!localStorage.getItem('access_token'),
  setAuth: (user: User, token: string, refreshToken: string) => {
    localStorage.setItem('user', JSON.stringify(user))
    localStorage.setItem('access_token', token)
    localStorage.setItem('refresh_token', refreshToken)
    notifyListeners()
  },
  logout: () => {
    localStorage.removeItem('user')
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    notifyListeners()
  },
  subscribe: (fn: () => void) => {
    _listeners.push(fn)
    return () => { _listeners = _listeners.filter((l) => l !== fn) }
  },
}
