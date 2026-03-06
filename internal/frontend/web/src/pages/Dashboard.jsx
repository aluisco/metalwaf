import { useEffect, useState, useCallback } from 'react'
import { analytics } from '../api.js'
import {
  Grid, Card, Text, Title, Stack, Skeleton, Alert,
  Group, ThemeIcon, RingProgress, Table, Badge, Divider, Box
} from '@mantine/core'
import { LineChart } from '@mantine/charts'
import {
  IconActivityHeartbeat, IconBan, IconShieldBolt,
  IconChartBar, IconAlertTriangle, IconCircleCheck, IconClock
} from '@tabler/icons-react'

export default function Dashboard() {
  const [data, setData]           = useState(null)
  const [alerts, setAlerts]       = useState([])
  const [threats, setThreats]     = useState([])
  const [loadingThreats, setLoadingThreats] = useState(true)
  const [error, setError]         = useState('')

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

    // Refresh metrics + alerts every 30 seconds
    const id = setInterval(fetchMetrics, 30_000)
    return () => clearInterval(id)
  }, [fetchMetrics])

  if (error) return <Alert color="red" icon={<IconAlertTriangle size={16} />}>{error}</Alert>
  if (!data) return (
    <Stack gap="lg">
      <Skeleton h={32} w={200} />
      <Grid gutter="md">
        {[...Array(4)].map((_, i) => <Grid.Col key={i} span={{ base: 12, sm: 6, lg: 3 }}><Skeleton h={110} radius="md" /></Grid.Col>)}
      </Grid>
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 8 }}><Skeleton h={280} radius="md" /></Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}><Skeleton h={280} radius="md" /></Grid.Col>
      </Grid>
      <Skeleton h={200} radius="md" />
    </Stack>
  )

  const blockRate = (data.block_rate_24h ?? 0) * 100
  const ringColor = blockRate > 30 ? 'red' : blockRate > 10 ? 'orange' : 'teal'

  const statCards = [
    {
      label: 'Requests (24h)',
      value: fmt(data.requests_24h),
      sub:   `${fmt(data.requests_total)} total all time`,
      icon:  IconActivityHeartbeat,
      color: 'blue',
    },
    {
      label: 'Blocked (24h)',
      value: fmt(data.blocked_24h),
      sub:   `${fmt(data.blocked_total)} total blocked`,
      icon:  IconBan,
      color: 'red',
    },
    {
      label: 'Block rate',
      value: `${blockRate.toFixed(1)}%`,
      sub:   'of requests in last 24h',
      icon:  IconShieldBolt,
      color: blockRate > 20 ? 'red' : 'orange',
    },
    {
      label: 'Req / min',
      value: fmt(data.requests_per_min ?? 0),
      sub:   `${fmt(data.blocked_per_min ?? 0)} blocked last min`,
      icon:  IconClock,
      color: 'violet',
    },
  ]

  // Build the 60-minute traffic sparkline from the aggregator data
  const chartData = (() => {
    const raw = data.traffic_60min ?? []
    if (raw.length === 0) {
      // Fallback when no aggregator data is available yet
      return [
        { label: 'All time', requests: data.requests_total, blocked: data.blocked_total },
        { label: 'Last 24h', requests: data.requests_24h,   blocked: data.blocked_24h   },
      ]
    }
    return raw.map(m => ({
      label:    new Date(m.unix_minute * 60 * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      requests: m.total,
      blocked:  m.blocked,
    }))
  })()

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="center">
        <Group gap="xs">
          <ThemeIcon size={36} variant="gradient" gradient={{ from: 'teal', to: 'cyan', deg: 135 }} radius="md">
            <IconChartBar size={20} />
          </ThemeIcon>
          <Title order={2}>Dashboard</Title>
        </Group>
        <Text size="sm" c="dimmed">
          {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
        </Text>
      </Group>

      {/* Active alerts */}
      {alerts.map((a, i) => (
        <Alert key={i} color="orange" icon={<IconAlertTriangle size={16} />} title="Security alert">
          {a.message}
        </Alert>
      ))}

      {/* Stat cards */}
      <Grid gutter="md">
        {statCards.map(s => (
          <Grid.Col key={s.label} span={{ base: 12, sm: 6, lg: 3 }}>
            <Card withBorder padding="lg" radius="md" h="100%">
              <ThemeIcon size={44} radius="md" color={s.color} variant="light" mb="md">
                <s.icon size={22} />
              </ThemeIcon>
              <Text size="xl" fw={800} lh={1}>{s.value}</Text>
              <Text size="xs" tt="uppercase" fw={700} c={s.color} mt={4} mb={2}>{s.label}</Text>
              <Text size="xs" c="dimmed">{s.sub}</Text>
            </Card>
          </Grid.Col>
        ))}
      </Grid>

      {/* Chart + block rate */}
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Card withBorder padding="lg" radius="md" h="100%">
            <Group justify="space-between" mb="md">
              <Text fw={600} size="sm">
                {(data.traffic_60min ?? []).length > 0 ? 'Traffic — last 60 minutes' : 'Traffic overview'}
              </Text>
              <Badge variant="dot" color="teal" size="sm">Live</Badge>
            </Group>
            <LineChart
              h={230}
              data={chartData}
              dataKey="label"
              series={[
                { name: 'requests', color: 'teal.6', label: 'Requests' },
                { name: 'blocked',  color: 'red.6',  label: 'Blocked'  },
              ]}
              curveType="natural"
              withLegend
              withTooltip
              withDots
              gridAxis="xy"
            />
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card withBorder padding="lg" radius="md" h="100%">
            <Text fw={600} size="sm" mb="xl">Block rate (24h)</Text>
            <Group justify="center" mb="lg">
              <RingProgress
                size={150}
                thickness={16}
                roundCaps
                sections={[{ value: blockRate, color: ringColor }]}
                label={
                  <Stack gap={0} align="center">
                    <Text fw={800} size="xl" lh={1}>{blockRate.toFixed(1)}%</Text>
                    <Text size="xs" c="dimmed" mt={2}>blocked</Text>
                  </Stack>
                }
              />
            </Group>
            <Divider mb="md" />
            <Stack gap={8}>
              <Group justify="space-between">
                <Group gap={6}>
                  <Box w={8} h={8} style={{ borderRadius: '50%', background: 'var(--mantine-color-teal-6)' }} />
                  <Text size="sm" c="dimmed">Requests</Text>
                </Group>
                <Text size="sm" fw={600}>{fmt(data.requests_24h)}</Text>
              </Group>
              <Group justify="space-between">
                <Group gap={6}>
                  <Box w={8} h={8} style={{ borderRadius: '50%', background: 'var(--mantine-color-red-6)' }} />
                  <Text size="sm" c="dimmed">Blocked</Text>
                </Group>
                <Text size="sm" fw={600} c="red">{fmt(data.blocked_24h)}</Text>
              </Group>
              <Group justify="space-between">
                <Group gap={6}>
                  <Box w={8} h={8} style={{ borderRadius: '50%', background: 'var(--mantine-color-gray-5)' }} />
                  <Text size="sm" c="dimmed">Passed</Text>
                </Group>
                <Text size="sm" fw={600} c="teal">
                  {fmt((data.requests_24h ?? 0) - (data.blocked_24h ?? 0))}
                </Text>
              </Group>
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      {/* Top IPs + top paths */}
      {((data.top_ips ?? []).length > 0 || (data.top_paths ?? []).length > 0) && (
        <Grid gutter="md">
          {(data.top_ips ?? []).length > 0 && (
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Card withBorder padding="lg" radius="md">
                <Text fw={600} size="sm" mb="md">Top client IPs (24h)</Text>
                <Table fz="xs" highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>IP address</Table.Th>
                      <Table.Th ta="right">Requests</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {(data.top_ips ?? []).map((e, i) => (
                      <Table.Tr key={i}>
                        <Table.Td><Text ff="monospace" size="xs">{e.label}</Text></Table.Td>
                        <Table.Td ta="right"><Badge variant="light" color="blue" size="xs">{fmt(e.count)}</Badge></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Card>
            </Grid.Col>
          )}
          {(data.top_paths ?? []).length > 0 && (
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Card withBorder padding="lg" radius="md">
                <Text fw={600} size="sm" mb="md">Top paths (24h)</Text>
                <Table fz="xs" highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Path</Table.Th>
                      <Table.Th ta="right">Requests</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {(data.top_paths ?? []).map((e, i) => (
                      <Table.Tr key={i}>
                        <Table.Td>
                          <Text ff="monospace" size="xs" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 260 }}>
                            {e.label}
                          </Text>
                        </Table.Td>
                        <Table.Td ta="right"><Badge variant="light" color="teal" size="xs">{fmt(e.count)}</Badge></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Card>
            </Grid.Col>
          )}
        </Grid>
      )}

      {/* Recent threats */}
      <Card withBorder padding="lg" radius="md">
        <Group justify="space-between" mb="md">
          <Group gap="xs">
            <ThemeIcon size={30} variant="light" color="red" radius="md">
              <IconAlertTriangle size={16} />
            </ThemeIcon>
            <Text fw={600}>Recent blocked requests</Text>
          </Group>
          <Badge color="red" variant="light" size="sm">{threats.length} shown</Badge>
        </Group>

        {loadingThreats ? (
          <Stack gap="xs">
            {[...Array(3)].map((_, i) => <Skeleton key={i} h={28} radius="sm" />)}
          </Stack>
        ) : threats.length === 0 ? (
          <Group justify="center" py="xl" gap="xs">
            <ThemeIcon size={32} variant="light" color="teal" radius="xl">
              <IconCircleCheck size={18} />
            </ThemeIcon>
            <Text c="dimmed" size="sm">No blocked requests — all clear</Text>
          </Group>
        ) : (
          <Table fz="xs" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Time</Table.Th>
                <Table.Th>Client IP</Table.Th>
                <Table.Th>Method</Table.Th>
                <Table.Th>Host / Path</Table.Th>
                <Table.Th ta="right">Score</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {threats.map((t, i) => (
                <Table.Tr key={i}>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}>{fmtTime(t.timestamp)}</Table.Td>
                  <Table.Td><Text ff="monospace" size="xs" fw={600}>{t.client_ip}</Text></Table.Td>
                  <Table.Td>
                    <Badge size="xs" variant="light" color={methodColor(t.method)}>{t.method}</Badge>
                  </Table.Td>
                  <Table.Td maw={320} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <Text ff="monospace" size="xs">{t.host}{t.path}</Text>
                  </Table.Td>
                  <Table.Td ta="right">
                    <Badge color="red" variant="filled" size="xs" radius="sm">{t.threat_score}</Badge>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
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
  const map = { GET: 'blue', POST: 'teal', PUT: 'yellow', DELETE: 'red', PATCH: 'orange' }
  return map[m] ?? 'gray'
}
