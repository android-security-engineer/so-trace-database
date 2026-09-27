import axios from 'axios'
import type { AuthResponse } from '../types'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
})

// Request interceptor: attach JWT token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor: handle 401
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const header = error.response.headers['x-setup-required']
      if (header === 'true') {
        localStorage.setItem('setup_required', 'true')
        window.location.href = '/setup'
      } else {
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  },
)

// Auth API
export const authApi = {
  checkStatus: () => api.get('/auth/status'),
  setup: (data: { username: string; password: string }) =>
    api.post<AuthResponse>('/auth/setup', data),
  login: (data: { username: string; password: string }) =>
    api.post<AuthResponse>('/auth/login', data),
  refresh: () => api.post<AuthResponse>('/auth/refresh'),
}

// SO Files API
export const soFileApi = {
  list: () => api.get('/so-files'),
  get: (id: number) => api.get(`/so-files/${id}`),
  create: (formData: FormData) =>
    api.post('/so-files', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  getFunctions: (id: number) => api.get(`/so-files/${id}/functions`),
  getSymbols: (id: number) => api.get(`/so-files/${id}/symbols`),
  getSegments: (id: number) => api.get(`/so-files/${id}/segments`),
}

// Traces API
export const traceApi = {
  list: () => api.get('/traces'),
  get: (id: number) => api.get(`/traces/${id}`),
  import: (formData: FormData) =>
    api.post('/traces/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  queryInstructions: (traceId: number, params: Record<string, string>) =>
    api.get(`/traces/${traceId}/instructions`, { params }),
  queryCallChain: (traceId: number, params?: Record<string, string>) =>
    api.get(`/traces/${traceId}/call-chain`, { params }),
  rebuildCallStack: (traceId: number, seq: number) =>
    api.get(`/traces/${traceId}/call-stack/${seq}`),
  queryMemorySnapshot: (traceId: number, seq: number) =>
    api.get(`/traces/${traceId}/memory/${seq}`),
  queryMemoryValue: (traceId: number, seq: number, address: string) =>
    api.get(`/traces/${traceId}/memory/${seq}/${address}`),
  queryRegisters: (traceId: number, seq: number) =>
    api.get(`/traces/${traceId}/registers/${seq}`),
  queryJniCalls: (traceId: number, params?: Record<string, string>) =>
    api.get(`/traces/${traceId}/jni-calls`, { params }),
}

// Stats API
export const statsApi = {
  get: () => api.get('/stats'),
}

export default api
