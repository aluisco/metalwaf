import { useCallback, useEffect, useState } from 'react'
import { analytics as api, sites as sitesApi } from '../api.js'
import {
  Stack, Title, Group, Button, Table, Badge, Select,
  TextInput, Text, Skeleton, Alert, Card
} from '@mantine/core'

const PAGE = 50

export default function Analytics() {
  const [siteList, setSiteList] = useState([])
  const [filters, setFilters]   = useState({ site_id:'', ip:'', blocked:'', from:'', to:'' })
  const [rows, setRows]         = useState([])
  const [offset, setOffset]     = useState(0)
  const [hasMore, setHasMore]   = useState(false)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  useEffect(() => { sitesApi.list().then(setSiteList).catch(() => {}) }, [])

  const load = useCallback((off = 0) => {
    setLoading(true); setError('')
    const params = { limit: PAGE + 1, offset: off }
    if (filters.site_id)          params.site_id  = +filters.site_id
    if (filters.ip)               params.ip       = filters.ip
    if (filters.blocked !== '')   params.blocked  = filters.blocked === 'true'
    if (filters.from)             params.from     = filters.from
    if (filters.to)               params.to       = filters.to

    api.logs(params)
      .then(data => {
        const all   = Array.isArray(data) ? data : (data.logs ?? [])
        const slice = all.slice(0, PAGE)
        if (off === 0) setRows(slice); else setRows(r => [...r, ...slice])
        setHasMore(all.length > PAGE)
        setOffset(off + slice.length)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [filters])

  useEffect(() => { load(0) }, [load])

  const siteOptions = [
    { value: '', label: 'All sites' },
    ...siteList.map(s => ({ value: String(s.id), label: s.name })),
  ]
  const blockedOptions = [
    { value: '', label: 'Any' },
    { value: 'true', label: 'Blocked' },
    { value: 'false', label: 'Passed' },
  ]

  return (
    <Stack>
      <Title order={2}>Analytics</Title>

      {/* Filter bar */}
      <Card withBorder padding="md">
        <form onSubmit={e => { e.preventDefault(); load(0) }}>
          <Group gap="sm" align="flex-end" wrap="wrap">
            <Select
              label="Site" size="sm" w={160}
              data={siteOptions}
              value={filters.site_id}
              onChange={v => setFilters(f=>({...f,site_id:v??''}))}
            />
            <TextInput
              label="Client IP" size="sm" w={140}
              placeholder="1.2.3.4"
              value={filters.ip}
              onChange={e => setFilters(f=>({...f,ip:e.target.value}))}
            />
            <Select
              label="Status" size="sm" w={120}
              data={blockedOptions}
              value={filters.blocked}
              onChange={v => setFilters(f=>({...f,blocked:v??''}))}
            />
            <TextInput
              label="From" size="sm" type="datetime-local" w={200}
              value={filters.from}
              onChange={e => setFilters(f=>({...f,from:e.target.value}))}
            />
            <TextInput
              label="To" size="sm" type="datetime-local" w={200}
              value={filters.to}
              onChange={e => setFilters(f=>({...f,to:e.target.value}))}
            />
            <Button type="submit" size="sm" mt={22}>Apply</Button>
          </Group>
        </form>
      </Card>

      {error && <Alert color="red">{error}</Alert>}

      {rows.length === 0 && !loading ? (
        <Text c="dimmed">No log entries found.</Text>
      ) : (
        <Table striped withTableBorder withColumnBorders fz="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Time</Table.Th><Table.Th>IP</Table.Th><Table.Th>Method</Table.Th>
              <Table.Th>Host / Path</Table.Th><Table.Th>Status</Table.Th>
              <Table.Th>Duration</Table.Th><Table.Th>Score</Table.Th><Table.Th>Blocked</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((r, i) => (
              <Table.Tr key={i}>
                <Table.Td style={{whiteSpace:'nowrap'}}>{fmtTime(r.timestamp)}</Table.Td>
                <Table.Td><Text ff="monospace" size="xs">{r.client_ip}</Text></Table.Td>
                <Table.Td><MethodBadge method={r.method}/></Table.Td>
                <Table.Td maw={260} style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                  <Text ff="monospace" size="xs">{r.host}{r.path}</Text>
                </Table.Td>
                <Table.Td><StatusBadge status={r.status_code}/></Table.Td>
                <Table.Td>{r.duration_ms}ms</Table.Td>
                <Table.Td>{r.threat_score}</Table.Td>
                <Table.Td>
                  {r.blocked
                    ? <Badge color="red"  variant="light" size="sm">blocked</Badge>
                    : <Badge color="gray" variant="light" size="sm">passed</Badge>}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      {loading && rows.length === 0 && <Skeleton h={200} />}

      {hasMore && (
        <Group justify="center">
          <Button variant="default" loading={loading} onClick={() => load(offset)}>
            Load more
          </Button>
        </Group>
      )}
    </Stack>
  )
}

function fmtTime(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString()
}

function MethodBadge({ method }) {
  const map = { GET:'blue', POST:'teal', PUT:'yellow', DELETE:'red', PATCH:'yellow' }
  return <Badge color={map[method] ?? 'gray'} variant="light" size="sm">{method}</Badge>
}

function StatusBadge({ status }) {
  if (!status)    return <Badge color="gray" variant="light" size="sm">—</Badge>
  if (status >= 500) return <Badge color="red"    variant="light" size="sm">{status}</Badge>
  if (status >= 400) return <Badge color="orange" variant="light" size="sm">{status}</Badge>
  if (status >= 300) return <Badge color="blue"   variant="light" size="sm">{status}</Badge>
  return <Badge color="teal" variant="light" size="sm">{status}</Badge>
}
