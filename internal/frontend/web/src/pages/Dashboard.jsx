import { useEffect, useState } from 'react'
import { analytics } from '../api.js'
import { SimpleGrid, Card, Text, Title, Stack, Skeleton, Alert } from '@mantine/core'
import { LineChart } from '@mantine/charts'


export default function Dashboard() {
  const [data, setData]   = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    analytics.metrics().then(setData).catch(e => setError(e.message))
  }, [])

  if (error) return <Alert color="red">{error}</Alert>
  if (!data)  return (
    <Stack>
      <Skeleton h={32} w={200} />
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 5 }}>
        {[...Array(5)].map((_, i) => <Skeleton key={i} h={90} radius="md" />)}
      </SimpleGrid>
      <Skeleton h={280} />
    </Stack>
  )

  const stats = [
    { label: 'Requests (24h)',   value: data.requests_24h,    color: undefined },
    { label: 'Blocked (24h)',    value: data.blocked_24h,     color: 'red'     },
    { label: 'Block rate (24h)', value: `${((data.block_rate_24h ?? 0) * 100).toFixed(1)}%`, color: 'orange' },
    { label: 'Total requests',   value: data.requests_total,  color: undefined },
    { label: 'Total blocked',    value: data.blocked_total,   color: 'red'     },
  ]

  const chartData = data.chart ?? [
    { label: 'All time', requests: data.requests_total, blocked: data.blocked_total },
    { label: 'Last 24h', requests: data.requests_24h,   blocked: data.blocked_24h   },
  ]

  return (
    <Stack>
      <Title order={2}>Dashboard</Title>

      <SimpleGrid cols={{ base: 1, sm: 2, lg: 5 }} spacing="md">
        {stats.map(s => (
          <Card key={s.label} withBorder padding="md" radius="md">
            <Text size="xs" c="dimmed" tt="uppercase" fw={600} mb={4}>{s.label}</Text>
            <Text size="xl" fw={700} c={s.color}>{fmt(s.value)}</Text>
          </Card>
        ))}
      </SimpleGrid>

      <Card withBorder padding="md" radius="md">
        <Text size="sm" fw={600} mb="md">Traffic overview</Text>
        <LineChart
          h={260}
          data={chartData}
          dataKey="label"
          series={[
            { name: 'requests', color: 'teal.6',   label: 'Requests' },
            { name: 'blocked',  color: 'red.6',    label: 'Blocked'  },
          ]}
          curveType="natural"
          withLegend
          withTooltip
          withDots
        />
      </Card>
    </Stack>
  )
}

function fmt(n) {
  if (n == null) return '—'
  return Number(n).toLocaleString()
}
