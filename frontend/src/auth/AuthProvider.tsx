import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'
import { authApi } from '../api/client'

interface AuthContextType {
  isAuthenticated: boolean
  isSetupRequired: boolean
  isLoading: boolean
  username: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  setup: (username: string, password: string) => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isSetupRequired, setIsSetupRequired] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [username, setUsername] = useState<string | null>(null)

  useEffect(() => {
    // Check if already authenticated
    const token = localStorage.getItem('access_token')
    const setupRequired = localStorage.getItem('setup_required')

    if (setupRequired === 'true') {
      setIsSetupRequired(true)
      setIsLoading(false)
      return
    }

    if (token) {
      setIsAuthenticated(true)
      setUsername(localStorage.getItem('username'))
    }

    // Check server status
    authApi.checkStatus().then((res) => {
      if (res.data?.setup_required) {
        setIsSetupRequired(true)
        localStorage.setItem('setup_required', 'true')
      }
    }).catch(() => {
      // Server might not be running
    }).finally(() => {
      setIsLoading(false)
    })
  }, [])

  const login = async (user: string, password: string) => {
    const res = await authApi.login({ username: user, password })
    localStorage.setItem('access_token', res.data.access_token)
    localStorage.setItem('refresh_token', res.data.refresh_token)
    localStorage.setItem('username', user)
    setIsAuthenticated(true)
    setUsername(user)
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('username')
    setIsAuthenticated(false)
    setUsername(null)
  }

  const setup = async (user: string, password: string) => {
    const res = await authApi.setup({ username: user, password })
    localStorage.setItem('access_token', res.data.access_token)
    localStorage.setItem('refresh_token', res.data.refresh_token)
    localStorage.setItem('username', user)
    localStorage.removeItem('setup_required')
    setIsAuthenticated(true)
    setIsSetupRequired(false)
    setUsername(user)
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, isSetupRequired, isLoading, username, login, logout, setup }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
