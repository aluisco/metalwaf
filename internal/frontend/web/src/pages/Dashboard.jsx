import { useEffect, useState, useCallback } from 'react'
import { analytics } from '../api.js'
import {
  CRow, CCol, CCard, CCardBody, CCardHeader,
  CAlert, CSpinner, CBadge,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell
} from '@coreui/react'
import { CChart } from '@coreui/react-chartjs'

export default function Dashboard() {
  const [data, setData]                   = useState(null)
  const [alerts, setAlerts]               = useState([])
  const [threats, setThreats]             = useState([])
  const [loadingThreats, setLoadingThreats] = useState(true)
  const [error, setError]                 = useState('')

  const fetchMetrics = useCallback(() => {
    analytics.metrics().then(setData).catch(e => setError(e.message))
    analytics.alerts().then(r => setAlerts(r.alerts ?? [])).catch(() => {})
  }, [])

  useEffect(() => {
    fetchMetrics()
    analytics.logs({ blocked: true, limit: 6 })
      .then(d => setThreats(Array.isArray(d) ? d : (d.logs ?? [])))
      .catch(() => {})
      .finally(() => setLoadingThreats(false))
    const id = setInterval(fetchMetrics, 30_000)
    return () => clearInterval(id)
  }, [fetchMetrics])

  if (error) return <CAlert color="danger">{error}</CAlert>
  if (!data) return <div className="text-center py-5"><CSpinner color="primary" /></div>

  const blockRate = (data.block_rate_24h ?? 0) * 100
  const blockColor = blockRate > 30 ? 'danger' : blockRate > 10 ? 'warning' : 'success'

  const statCards = [
    { label: 'Requests (24h)', value: fmt(data.requests_24h), sub: `${fmt(data.requests_total)} total`, color: 'info' },
    { label: 'Blocked (24h)',  value: fmt(data.blocked_24h),  sub: `${fmt(data.blocked_total)} total`,  color: 'danger' },
    { label: 'Block rate',     value: `${blockRate.toFixed(1)}%`, sub: 'in last 24h',                   color: blockColor },
    { label: 'Req / min',      value: fmt(data.requests_per_min ?? 0), sub: `${fmt(data.blocked_per_min ?? 0)} blocked last min`, color: 'primary' },
  ]

  const raw = data.traffic_60min ?? []
  const chartLabels = raw.length > 0
    ? raw.map(m => new Date(m.unix_minute * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
    : ['All time', 'Last 24h']
  const chartRequests = raw.length > 0 ? raw.map(m => m.total)   : [data.requests_total, data.requests_24h]
  const chartBlocked  = raw.length > 0 ? raw.map(m => m.blocked) : [data.blocked_total, data.blocked_24h]

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="mb-0 fw-semibold">Dashboard</h2>
        <small className="text-body-secondary">
          {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
        </small>
      </div>

      {/* Security alerts */}
      {alerts.map((a, i) => (
        <CAlert key={i} color="warning">⚠ {a.message}</CAlert>
      ))}

      {/* Stat cards */}
      <CRow className="mb-4 g-3">
        {statCards.map(s => (
          <CCol key={s.label} xs={12} sm={6} xl={3}>
            <CCard className={`border-top border-top-${s.color} h-100`}>
              <CCardBody>
                <div className="fs-4 fw-bold">{s.value}</div>
                <div className={`text-${s.color} text-uppercase small fw-semibold mb-1`}>{s.label}</div>
                <div className="text-body-secondary small">{s.sub}</div>
              </CCardBody>
            </CCard>
          </CCol>
        ))}
      </CRow>

      {/* Chart + block rate ring */}
      <CRow className="mb-4 g-3">
        <CCol xs={12} lg={8}>
          <CCard className="h-100">
            <CCardHeader className="d-flex justify-content-between align-items-center">
              <span className="fw-semibold">
                {raw.length > 0 ? 'Traffic — last 60 minutes' : 'Traffic overview'}
              </span>
              <CBadge color="success">● Live</CBadge>
            </CCardHeader>
            <CCardBody>
              <CChart
                type="line"
                data={{
                  labels: chartLabels,
                  datasets: [
                    {
                      label: 'Requests',
                      data: chartRequests,
                      borderColor: 'rgba(50,200,160,1)',
                      backgroundColor: 'rgba(50,200,160,0.1)',
                      tension: 0.4,
                      fill: true,
                    },
                    {
                      label: 'Blocked',
                      data: chartBlocked,
                      borderColor: 'rgba(220,53,69,1)',
                      backgroundColor: 'rgba(220,53,69,0.1)',
                      tension: 0.4,
                      fill: true,
                    },
                  ],
                }}
                options={{
                  plugins: { legend: { position: 'bottom' } },
                  scales: { y: { beginAtZero: true } },
                  maintainAspectRatio: true,
                }}
                style={{ maxHeight: 240 }}
              />
            </CCardBody>
          </CCard>
        </CCol>

        <CCol xs={12} lg={4}>
          <CCard className="h-100">
            <CCardHeader><span className="fw-semibold">Block rate (24h)</span></CCardHeader>
            <CCardBody className="d-flex flex-column align-items-center justify-content-center">
              <CChart
                type="doughnut"
                data={{
                  labels: ['Blocked', 'Passed'],
                  datasets: [{
                    data: [
                      Math.round(blockRate * 10) / 10,
                      Math.round((100 - blockRate) * 10) / 10,
                    ],
                    backgroundColor: ['rgba(220,53,69,0.8)', 'rgba(50,200,160,0.4)'],
                    borderWidth: 0,
                  }],
                }}
                options={{
                  plugins: {
                    legend: { display: false },
                    tooltip: { callbacks: { label: ctx => `${ctx.parsed}%` } },
                  },
                  cutout: '72%',
                  maintainAspectRatio: true,
                }}
                style={{ maxHeight: 160 }}
              />
              <div className="text-center mt-3">
                <div className={`fs-4 fw-bold text-${blockColor}`}>{blockRate.toFixed(1)}%</div>
                <div className="text-body-secondary small">blocked</div>
              </div>
              <hr className="w-100" />
              <div className="w-100 small">
                <div className="d-flex justify-content-between"><span className="text-body-secondary">Requests</span><strong>{fmt(data.requests_24h)}</strong></div>
                <div className="d-flex justify-content-between"><span className="text-body-secondary">Blocked</span><strong className="text-danger">{fmt(data.blocked_24h)}</strong></div>
              </div>
            </CCardBody>
          </CCard>
        </CCol>
      </CRow>

      {/* Top IPs + paths */}
      {((data.top_ips ?? []).length > 0 || (data.top_paths ?? []).length > 0) && (
        <CRow className="mb-4 g-3">
          {(data.top_ips ?? []).length > 0 && (
            <CCol xs={12} lg={6}>
              <CCard>
                <CCardHeader><span className="fw-semibold">Top client IPs (24h)</span></CCardHeader>
                <CCardBody className="p-0">
                  <CTable small hover className="mb-0">
                    <CTableHead><CTableRow>
                      <CTableHeaderCell>IP Address</CTableHeaderCell>
                      <CTableHeaderCell className="text-end">Requests</CTableHeaderCell>
                    </CTableRow></CTableHead>
                    <CTableBody>
                      {(data.top_ips ?? []).map((e, i) => (
                        <CTableRow key={i}>
                          <CTableDataCell><code>{e.label}</code></CTableDataCell>
                          <CTableDataCell className="text-end"><CBadge color="info">{fmt(e.count)}</CBadge></CTableDataCell>
                        </CTableRow>
                      ))}
                    </CTableBody>
                  </CTable>
                </CCardBody>
              </CCard>
            </CCol>
          )}
          {(data.top_paths ?? []).length > 0 && (
            <CCol xs={12} lg={6}>
              <CCard>
                <CCardHeader><span className="fw-semibold">Top paths (24h)</span></CCardHeader>
                <CCardBody className="p-0">
                  <CTable small hover className="mb-0">
                    <CTableHead><CTableRow>
                      <CTableHeaderCell>Path</CTableHeaderCell>
                      <CTableHeaderCell className="text-end">Requests</CTableHeaderCell>
                    </CTableRow></CTableHead>
                    <CTableBody>
                      {(data.top_paths ?? []).map((e, i) => (
                        <CTableRow key={i}>
                          <CTableDataCell style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            <code>{e.label}</code>
                          </CTableDataCell>
                          <CTableDataCell className="text-end"><CBadge color="success">{fmt(e.count)}</CBadge></CTableDataCell>
                        </CTableRow>
                      ))}
                    </CTableBody>
                  </CTable>
                </CCardBody>
              </CCard>
            </CCol>
          )}
        </CRow>
      )}

      {/* Recent threats */}
      <CCard>
        <CCardHeader className="d-flex justify-content-between align-items-center">
          <span className="fw-semibold">🛡 Recent blocked requests</span>
          <CBadge color="danger">{threats.length} shown</CBadge>
        </CCardHeader>
        <CCardBody className="p-0">
          {loadingThreats ? (
            <div className="text-center py-4"><CSpinner size="sm" /></div>
          ) : threats.length === 0 ? (
            <div className="text-center py-4 text-body-secondary">✓ No blocked requests — all clear</div>
          ) : (
            <CTable small hover responsive className="mb-0">
              <CTableHead>
                <CTableRow>
                  <CTableHeaderCell>Time</CTableHeaderCell>
                  <CTableHeaderCell>Client IP</CTableHeaderCell>
                  <CTableHeaderCell>Method</CTableHeaderCell>
                  <CTableHeaderCell>Host / Path</CTableHeaderCell>
                  <CTableHeaderCell className="text-end">Score</CTableHeaderCell>
                </CTableRow>
              </CTableHead>
              <CTableBody>
                {threats.map((t, i) => (
                  <CTableRow key={i}>
                    <CTableDataCell style={{ whiteSpace: 'nowrap' }}>{fmtTime(t.timestamp)}</CTableDataCell>
                    <CTableDataCell><code className="fw-bold">{t.client_ip}</code></CTableDataCell>
                    <CTableDataCell><CBadge color={methodColor(t.method)}>{t.method}</CBadge></CTableDataCell>
                    <CTableDataCell style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <code>{t.host}{t.path}</code>
                    </CTableDataCell>
                    <CTableDataCell className="text-end"><CBadge color="danger">{t.threat_score}</CBadge></CTableDataCell>
                  </CTableRow>
                ))}
              </CTableBody>
            </CTable>
          )}
        </CCardBody>
      </CCard>
    </>
  )
}

function fmt(n) {
  if (n == null) return '—'
  return Number(n).toLocaleString()
}

function fmtTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function methodColor(m) {
  const map = { GET: 'info', POST: 'success', PUT: 'warning', DELETE: 'danger', PATCH: 'warning' }
  return map[m] ?? 'secondary'
}

