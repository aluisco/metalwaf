/**
 * MetalWAF API client.
 *
 * All requests are sent to the Go admin server at /api/v1.
 * Access tokens are stored in memory; refresh tokens in localStorage.
 * The client automatically refreshes the access token on 401 responses
 * and retries the original request exactly once.
 */

const BASE = '/api/v1'
const RT_KEY = 'mwaf_rt'

let _accessToken = null
let _refreshing = null // Promise<void> | null  (singleton refresh gate)

// ── Token storage ─────────────────────────────────────────────────────────────

export function setTokens({ access_token, refresh_token }) {
  _accessToken = access_token
  if (refresh_token) localStorage.setItem(RT_KEY, refresh_token)
}

export function clearTokens() {
  _accessToken = null
  localStorage.removeItem(RT_KEY)
}

export function getRefreshToken() {
  return localStorage.getItem(RT_KEY)
}

export function isLoggedIn() {
  return !!getRefreshToken()
}

// ── Core fetch wrapper ────────────────────────────────────────────────────────

async function _refresh() {
  const rt = getRefreshToken()
  if (!rt) throw new Error('no refresh token')
  const res = await fetch(`${BASE}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: rt }),
  })
  if (!res.ok) {
    clearTokens()
    throw new Error('session expired')
  }
  const { data } = await res.json()
  setTokens(data)
}

/**
 * apiFetch wraps fetch with:
 *   - Authorization: Bearer <access_token> header injection
 *   - Automatic token refresh on 401 + single retry
 *   - Unwraps the {"data":...} / {"error":"..."} envelope
 */
export async function apiFetch(path, options = {}) {
  const doRequest = async () => {
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    }
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`

    const res = await fetch(`${BASE}${path}`, { ...options, headers })
    return res
  }

  let res = await doRequest()

  if (res.status === 401 && getRefreshToken()) {
    // Ensure only one concurrent refresh happens
    if (!_refreshing) {
      _refreshing = _refresh().finally(() => { _refreshing = null })
    }
    try {
      await _refreshing
    } catch (_) {
      // Refresh failed — caller will handle redirect to login
      throw new ApiError(401, 'session expired')
    }
    res = await doRequest()
  }

  if (res.status === 204) return null

  const body = await res.json()
  if (!res.ok) {
    throw new ApiError(res.status, body.error || 'unknown error')
  }
  return body.data !== undefined ? body.data : body
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export const auth = {
  login: (username, password, totp_code) =>
    apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, ...(totp_code ? { totp_code } : {}) }),
    }),
  logout: () => apiFetch('/auth/logout', { method: 'POST' }),
  logoutAll: () => apiFetch('/auth/logout-all', { method: 'POST' }),
}

// ── Profile ───────────────────────────────────────────────────────────────────

export const profile = {
  get: () => apiFetch('/profile'),
  changePassword: (current_password, new_password) =>
    apiFetch('/profile/password', {
      method: 'PUT',
      body: JSON.stringify({ current_password, new_password }),
    }),
  setupTOTP: () => apiFetch('/auth/totp/setup', { method: 'POST' }),
  verifyTOTP: (code) =>
    apiFetch('/auth/totp/verify', { method: 'POST', body: JSON.stringify({ code }) }),
  disableTOTP: (code) =>
    apiFetch('/auth/totp/disable', { method: 'POST', body: JSON.stringify({ code }) }),
}

// ── Sites & Upstreams ─────────────────────────────────────────────────────────

export const sites = {
  list: () => apiFetch('/sites'),
  get: (id) => apiFetch(`/sites/${id}`),
  create: (data) => apiFetch('/sites', { method: 'POST', body: JSON.stringify(data) }),
  update: (id, data) => apiFetch(`/sites/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id) => apiFetch(`/sites/${id}`, { method: 'DELETE' }),
  listUpstreams: (id) => apiFetch(`/sites/${id}/upstreams`),
  createUpstream: (id, data) =>
    apiFetch(`/sites/${id}/upstreams`, { method: 'POST', body: JSON.stringify(data) }),
  updateUpstream: (siteId, uid, data) =>
    apiFetch(`/sites/${siteId}/upstreams/${uid}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteUpstream: (siteId, uid) =>
    apiFetch(`/sites/${siteId}/upstreams/${uid}`, { method: 'DELETE' }),
}

// ── WAF Rules ─────────────────────────────────────────────────────────────────

export const rules = {
  list: (siteId) => apiFetch(`/rules${siteId ? `?site_id=${siteId}` : ''}`),
  get: (id) => apiFetch(`/rules/${id}`),
  create: (data) => apiFetch('/rules', { method: 'POST', body: JSON.stringify(data) }),
  update: (id, data) => apiFetch(`/rules/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id) => apiFetch(`/rules/${id}`, { method: 'DELETE' }),
}

// ── Certificates ──────────────────────────────────────────────────────────────

export const certs = {
  list: () => apiFetch('/certificates'),
  get: (id) => apiFetch(`/certificates/${id}`),
  upload: (data) => apiFetch('/certificates', { method: 'POST', body: JSON.stringify(data) }),
  delete: (id) => apiFetch(`/certificates/${id}`, { method: 'DELETE' }),
  requestACME: (domain) =>
    apiFetch('/certificates/letsencrypt', { method: 'POST', body: JSON.stringify({ domain }) }),
}

// ── Analytics ─────────────────────────────────────────────────────────────────

export const analytics = {
  metrics: () => apiFetch('/metrics'),
  logs: (params = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => v != null && q.set(k, v))
    const qs = q.toString()
    return apiFetch(`/logs${qs ? `?${qs}` : ''}`)
  },
}

// ── Settings ──────────────────────────────────────────────────────────────────

export const settings = {
  getAll: () => apiFetch('/settings'),
  set: (key, value) =>
    apiFetch(`/settings/${encodeURIComponent(key)}`, {
      method: 'PUT',
      body: JSON.stringify({ value }),
    }),
}
