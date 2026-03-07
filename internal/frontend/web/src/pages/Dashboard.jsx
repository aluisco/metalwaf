import { useEffect, useState, useCallback } from 'react'
import { analytics } from '../api.js'
import {
  CRow, CCol, CCard, CCardBody, CCardHeader,
  CAlert, CSpinner, CBadge,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell,
  CWidgetStatsA,
} from '@coreui/react'
import { CChartLine, CChartDoughnut } from '@coreui/react-chartjs'
import CIcon from '@coreui/icons-react'
import { cilArrowTop, cilArrowBottom } from '@coreui/icons'

function Sparkline({ data }) {
  return (
    <CChartLine
      className="mt-3 mx-3"
      style={{ height: '70px' }}
      data={{
        labels: data.map((_, i) => String(i)),
        datasets: [{
          data,
          borderColor: 'rgba(255,255,255,.55)',
          backgroundColor: 'transparent',
          borderWidth: 2,
          fill: false,
          pointRadius: 0,
          tension: 0.4,
        }],
      }}
      options={{
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        maintainAspectRatio: false,
        scales: {
          x: { border: { display: false }, grid: { display: false }, ticks: { display: false } },
          y: { min: -9, border: { display: false }, grid: { display: false }, ticks: { display: false } },
        },
      }}
    />
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

function ChangeLabel({ prev, curr }) {
  if (!prev || !curr) return null
  const pct = prev === 0 ? 0 : Math.round(((curr - prev) / prev) * 100)
  const up = pct >= 0
  return (
    <span className="fs-6 fw-normal" style={{ opacity: 0.75 }}>
      ({up ? '+' : ''}{pct}% <CIcon icon={up ? cilArrowTop : cilArrowBottom} />)
    </span>
  )
}

const N = 15 // sparkline points

export default function Dashboard() {
  const [data, setData]             = useState(null)
  const [alerts, setAlerts]         = useState([])
  const [threats, setThreats]       = useState([])
  const [loadingThreats, setLT]     = useState(true)
  const [error, setError]           = useState('')

  const fetchMetrics = useCallback(() => {
    analytics.metrics().then(setData).catch(e => setError(e.message))
    analytics.alerts().then(r => setAlerts(r?.alerts ?? [])).catch(() => {})
  }, [])

  useEffect(() => {
    fetchMetrics()
    analytics.logs({ blocked: true, limit: 8 })
      .then(d => setThreats(Array.isArray(d) ? d : (d?.logs ?? [])))
      .catch(() => {})
      .finally(() => setLT(false))
    const id = setInterval(fetchMetrics, 30_000)
    return () => clearInterval(id)
  }, [fetchMetrics])

  if (error) return <CAlert color="danger">{error}</CAlert>
  if (!data)  return <div className="text-center py-5"><CSpinner color="primary" /></div>

  const blockRate   = (data.block_rate_24h ?? 0) * 100
  const blockColor  = blockRate > 30 ? 'danger' : blockRate > 10 ? 'warning' : 'success'
  const raw         = data.traffic_60min ?? []
  const slice       = raw.length >= N ? raw.slice(-N) : [...Array(N - raw.length).fill({ total: 0, blocked: 0 }), ...raw]

  const reqSpark    = slice.map(m => m.total   ?? 0)
  const blkSpark    = slice.map(m => m.blocked ?? 0)
  const rateSpark   = slice.map(m => m.total > 0 ? Math.round((m.blocked / m.total) * 100) : 0)
  const rpmSpark    = Array(N).fill(data.requests_per_min ?? 0)

  const chartLabels   = raw.length > 0
    ? raw.map(m => new Date(m.unix_minute * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
    : ['Total', '24h']
  const chartRequests = raw.length > 0 ? raw.map(m => m.total)   : [data.requests_total, data.requests_24h]
  const chartBlocked  = raw.length > 0 ? raw.map(m => m.blocked) : [data.blocked_total,  data.blocked_24h]

  const widgets = [
    { color: 'primary',   title: 'Requests (24h)', value: fmt(data.requests_24h), sub: `${fmt(data.requests_total)} all-time`, spark: reqSpark  },
    { color: 'danger',    title: 'Blocked (24h)',  value: fmt(data.blocked_24h),  sub: `${fmt(data.blocked_total)} all-time`,  spark: blkSpark  },
    { color: blockColor === 'success' ? 'info' : blockColor, title: 'Block Rate', value: `${blockRate.toFixed(1)}%`, sub: 'last 24h', spark: rateSpark },
    { color: 'info',      title: 'Req / min',      value: fmt(data.requests_per_min ?? 0), sub: `${fmt(data.blocked_per_min ?? 0)} blocked/min`, spark: rpmSpark },
  ]

  return (
    <>
      {alerts.map((a, i) => <CAlert key={i} color="warning" className="mb-3">⚠ {a.message}</CAlert>)}

      {/* ── Stat widgets with sparklines ────────────────────────────── */}
      <CRow className="mb-4 g-3">
        {widgets.map(w => (
          <CCol key={w.title} xs={12} sm={6} lg={3}>
            <CWidgetStatsA
              color={w.color}
              value={
                <>
                  {w.value}{' '}
                  <span className="fs-6 fw-normal" style={{ opacity: 0.75 }}>{w.sub}</span>
                </>
              }
              title={w.title}
              chart={<Sparkline data={w.spark} />}
            />
          </CCol>
        ))}
      </CRow>

      {/* ── Traffic chart + block rate ───────────────────────────────── */}
      <CRow className="mb-4 g-3">
        <CCol xs={12} lg={8}>
          <CCard className="h-100">
            <CCardHeader className="d-flex justify-content-between align-items-center">
              <strong>{raw.length > 0 ? 'Traffic — last 60 minutes' : 'Traffic overview'}</strong>
              <CBadge color="success">● Live</CBadge>
            </CCardHeader>
            <CCardBody>
              <CChartLine
                style={{ height: '260px' }}
                data={{
                  labels: chartLabels,
                  datasets: [
                    { label: 'Requests', data: chartRequests, borderColor: 'rgba(50,200,160,1)',  backgroundColor: 'rgba(50,200,160,0.12)', tension: 0.4, fill: true, pointRadius: 0 },
                    { label: 'Blocked',  data: chartBlocked,  borderColor: 'rgba(220,53,69,1)',   backgroundColor: 'rgba(220,53,69,0.12)',  tension: 0.4, fill: true, pointRadius: 0 },
                  ],
                }}
                options={{ maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } }, scales: { y: { beginAtZero: true } } }}
              />
            </CCardBody>
          </CCard>
        </CCol>

        <CCol xs={12} lg={4}>
          <CCard className="h-100">
            <CCardHeader><strong>Block rate (24h)</strong></CCardHeader>
            <CCardBody className="d-flex flex-column align-items-center justify-content-center gap-3">
              <CChartDoughnut
                style={{ height: '160px' }}
                data={{
                  labels: ['Blocked', 'Passed'],
                  datasets: [{ data: [+blockRate.toFixed(1), +(100 - blockRate).toFixed(1)], backgroundColor: ['rgba(220,53,69,.9)', 'rgba(50,200,160,.4)'], borderWidth: 0 }],
                }}
                options={{ maintainAspectRatio: false, plugins: { legend: { display: false } }, cutout: '74%' }}
              />
              <div className="text-center">
                <div className={`fs-3 fw-bold text-${blockColor}`}>{blockRate.toFixed(1)}%</div>
                <div className="text-body-secondary small">of traffic blocked</div>
              </div>
              <div className="w-100 small border-top pt-3">
                <div className="d-flex justify-content-between mb-1"><span className="text-body-secondary">Requests (24h)</span><strong>{fmt(data.requests_24h)}</strong></div>
                <div className="d-flex justify-content-between"><span className="text-body-secondary">Blocked (24h)</span><strong className="text-danger">{fmt(data.blocked_24h)}</strong></div>
              </div>
            </CCardBody>
          </CCard>
        </CCol>
      </CRow>

      {/* ── Top IPs & Paths ──────────────────────────────────────────── */}
      {((data.top_ips ?? []).length > 0 || (data.top_paths ?? []).length > 0) && (
        <CRow className="mb-4 g-3">
          {(data.top_ips ?? []).length > 0 && (
            <CCol xs={12} lg={6}>
              <CCard>
                <CCardHeader><strong>Top client IPs (24h)</strong></CCardHeader>
                <CCardBody className="p-0">
                  <CTable small hover className="mb-0">
                    <CTableHead><CTableRow>
                      <CTableHeaderCell>#</CTableHeaderCell>
                      <CTableHeaderCell>IP</CTableHeaderCell>
                      <CTableHeaderCell className="text-end">Requests</CTableHeaderCell>
                    </CTableRow></CTableHead>
                    <CTableBody>
                      {data.top_ips.map((e, i) => (
                        <CTableRow key={i}>
                          <CTableDataCell className="text-body-secondary">{i + 1}</CTableDataCell>
                          <CTableDataCell><code>{e.label}</code></CTableDataCell>
                          <CTableDataCell className="text-end"><CBadge color="primary">{fmt(e.count)}</CBadge></CTableDataCell>
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
                <CCardHeader><strong>Top paths (24h)</strong></CCardHeader>
                <CCardBody className="p-0">
                  <CTable small hover className="mb-0">
                    <CTableHead><CTableRow>
                      <CTableHeaderCell>#</CTableHeaderCell>
                      <CTableHeaderCell>Path</CTableHeaderCell>
                      <CTableHeaderCell className="text-end">Requests</CTableHeaderCell>
                    </CTableRow></CTableHead>
                    <CTableBody>
                      {data.top_paths.map((e, i) => (
                        <CTableRow key={i}>
                          <CTableDataCell className="text-body-secondary">{i + 1}</CTableDataCell>
                          <CTableDataCell style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            <code title={e.label}>{e.label}</code>
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

      {/* ── Recent blocked requests ──────────────────────────────────── */}
      <CCard>
        <CCardHeader className="d-flex justify-content-between align-items-center">
          <strong>Recent blocked requests</strong>
          <CBadge color="danger">{threats.length}</CBadge>
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
                    <CTableDataCell style={{ whiteSpace: 'nowrap' }}><small>{fmtTime(t.timestamp)}</small></CTableDataCell>
                    <CTableDataCell><code className="fw-bold">{t.client_ip}</code></CTableDataCell>
                    <CTableDataCell><CBadge color={methodColor(t.method)}>{t.method}</CBadge></CTableDataCell>
                    <CTableDataCell style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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
