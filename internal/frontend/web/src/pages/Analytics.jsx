import { useEffect, useState, useCallback } from 'react'
import { analytics as api } from '../api.js'
import {
  CAlert, CSpinner, CBadge, CButton,
  CFormInput, CFormLabel, CFormSelect,
  CRow, CCol, CCard, CCardBody, CCardHeader,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell,
} from '@coreui/react'

const STATUS_COLOR = { 200:'success',201:'success',204:'success',301:'info',302:'info',304:'info',400:'warning',401:'warning',403:'danger',404:'warning',429:'warning',500:'danger',503:'danger' }
function statusBadge(code) {
  const color = STATUS_COLOR[code] ?? (code >= 500 ? 'danger' : code >= 400 ? 'warning' : code >= 300 ? 'info' : 'success')
  return <CBadge color={color}>{code}</CBadge>
}

function methodBadge(method) {
  const colors = { GET:'primary',POST:'success',PUT:'warning',PATCH:'warning',DELETE:'danger',HEAD:'info',OPTIONS:'secondary' }
  return <CBadge color={colors[method] ?? 'secondary'}>{method}</CBadge>
}

const PAGE_SIZE = 50

export default function Analytics() {
  const now = new Date()
  const pad = n => String(n).padStart(2, '0')
  const toLocal = d => {
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  }
  const oneHourAgo = new Date(now - 3600000)

  const [filters, setFilters] = useState({
    from:   toLocal(oneHourAgo),
    to:     toLocal(now),
    site:   '',
    status: '',
    method: '',
    search: '',
  })
  const [logs,    setLogs]    = useState([])
  const [total,   setTotal]   = useState(0)
  const [page,    setPage]    = useState(1)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  const load = useCallback(async (p = 1, reset = true) => {
    setLoading(true)
    setError('')
    try {
      const params = {
        from:    filters.from ? new Date(filters.from).toISOString() : undefined,
        to:      filters.to   ? new Date(filters.to).toISOString()   : undefined,
        site:    filters.site   || undefined,
        status:  filters.status || undefined,
        method:  filters.method || undefined,
        q:       filters.search || undefined,
        page:    p,
        per_page: PAGE_SIZE,
      }
      const res = await api.logs(params)
      const rows  = Array.isArray(res) ? res : (res.logs ?? res.results ?? res.data ?? [])
      const count = typeof res?.total === 'number' ? res.total : rows.length
      setLogs(prev => reset ? rows : [...prev, ...rows])
      setTotal(count)
      setPage(p)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => { load(1, true) }, [])

  function handleSubmit(e) {
    e.preventDefault()
    load(1, true)
  }

  const hasMore = logs.length < total

  return (
    <>
      <h2 className="mb-4 fw-semibold">Analytics</h2>

      {/* Filter bar */}
      <CCard className="mb-4">
        <CCardHeader><strong>Filters</strong></CCardHeader>
        <CCardBody>
          <form onSubmit={handleSubmit}>
            <CRow className="g-3">
              <CCol xs={12} md={3}>
                <CFormLabel className="mb-1">From</CFormLabel>
                <CFormInput type="datetime-local" value={filters.from}
                  onChange={e => setFilters(f => ({...f, from: e.target.value}))} />
              </CCol>
              <CCol xs={12} md={3}>
                <CFormLabel className="mb-1">To</CFormLabel>
                <CFormInput type="datetime-local" value={filters.to}
                  onChange={e => setFilters(f => ({...f, to: e.target.value}))} />
              </CCol>
              <CCol xs={6} md={2}>
                <CFormLabel className="mb-1">Status</CFormLabel>
                <CFormSelect value={filters.status} onChange={e => setFilters(f => ({...f, status: e.target.value}))}>
                  <option value="">All</option>
                  {[200,301,400,401,403,404,429,500,503].map(s => <option key={s} value={s}>{s}</option>)}
                </CFormSelect>
              </CCol>
              <CCol xs={6} md={2}>
                <CFormLabel className="mb-1">Method</CFormLabel>
                <CFormSelect value={filters.method} onChange={e => setFilters(f => ({...f, method: e.target.value}))}>
                  <option value="">All</option>
                  {['GET','POST','PUT','PATCH','DELETE','HEAD'].map(m => <option key={m} value={m}>{m}</option>)}
                </CFormSelect>
              </CCol>
              <CCol xs={12} md={2}>
                <CFormLabel className="mb-1">Search</CFormLabel>
                <CFormInput placeholder="IP / path / …" value={filters.search}
                  onChange={e => setFilters(f => ({...f, search: e.target.value}))} />
              </CCol>
              <CCol xs={12} className="d-flex gap-2">
                <CButton type="submit" color="primary" disabled={loading}>
                  {loading ? <CSpinner size="sm" /> : 'Apply'}
                </CButton>
                <CButton type="button" color="secondary" variant="outline" onClick={() => {
                  setFilters({ from: toLocal(oneHourAgo), to: toLocal(now), site:'', status:'', method:'', search:'' })
                }}>Reset</CButton>
              </CCol>
            </CRow>
          </form>
        </CCardBody>
      </CCard>

      {error && <CAlert color="danger">{error}</CAlert>}

      {/* Summary */}
      {total > 0 && (
        <p className="text-body-secondary small mb-2">Showing {logs.length} of {total} entries</p>
      )}

      <CCard>
        <CCardBody className="p-0">
          <CTable bordered hover responsive className="mb-0">
            <CTableHead>
              <CTableRow>
                <CTableHeaderCell>Time</CTableHeaderCell>
                <CTableHeaderCell>Method</CTableHeaderCell>
                <CTableHeaderCell>Status</CTableHeaderCell>
                <CTableHeaderCell>Host</CTableHeaderCell>
                <CTableHeaderCell>Path</CTableHeaderCell>
                <CTableHeaderCell>Client IP</CTableHeaderCell>
                <CTableHeaderCell>Latency</CTableHeaderCell>
                <CTableHeaderCell>WAF Action</CTableHeaderCell>
              </CTableRow>
            </CTableHead>
            <CTableBody>
              {logs.length === 0 && !loading ? (
                <CTableRow>
                  <CTableDataCell colSpan={8} className="text-center text-body-secondary py-4">No log entries found</CTableDataCell>
                </CTableRow>
              ) : logs.map((r, i) => (
                <CTableRow key={i}>
                  <CTableDataCell><small>{new Date(r.time ?? r.timestamp).toLocaleString()}</small></CTableDataCell>
                  <CTableDataCell>{methodBadge(r.method)}</CTableDataCell>
                  <CTableDataCell>{statusBadge(r.status ?? r.status_code)}</CTableDataCell>
                  <CTableDataCell><small>{r.host}</small></CTableDataCell>
                  <CTableDataCell style={{ maxWidth: 260 }}>
                    <small className="text-truncate d-block" title={r.path}>{r.path}</small>
                  </CTableDataCell>
                  <CTableDataCell><small>{r.client_ip ?? r.remote_addr}</small></CTableDataCell>
                  <CTableDataCell><small>{r.latency_ms != null ? `${r.latency_ms} ms` : '—'}</small></CTableDataCell>
                  <CTableDataCell>
                    {r.waf_action ? (
                      <CBadge color={r.waf_action==='block'?'danger':r.waf_action==='detect'?'warning':'secondary'}>
                        {r.waf_action}
                      </CBadge>
                    ) : '—'}
                  </CTableDataCell>
                </CTableRow>
              ))}
            </CTableBody>
          </CTable>
        </CCardBody>
      </CCard>

      {hasMore && (
        <div className="text-center mt-3">
          <CButton color="secondary" variant="outline" disabled={loading} onClick={() => load(page + 1, false)}>
            {loading ? <CSpinner size="sm" /> : 'Load more'}
          </CButton>
        </div>
      )}
    </>
  )
}
