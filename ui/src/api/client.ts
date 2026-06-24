import axios from 'axios'

// In dev the Vite proxy forwards /api/* → http://localhost:8000/*
// In production set VITE_API_BASE_URL to the API origin.
const baseURL = import.meta.env.VITE_API_BASE_URL ?? '/api'

export const apiClient = axios.create({ baseURL })

// Token injected by AuthProvider via setAuthToken()
let _token: string | null = null

export function setAuthToken(token: string | null) {
  _token = token
}

apiClient.interceptors.request.use((config) => {
  if (_token) config.headers.Authorization = `Bearer ${_token}`
  return config
})
