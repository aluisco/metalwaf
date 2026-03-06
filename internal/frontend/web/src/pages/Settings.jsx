import { useEffect, useState } from 'react'
import { settings as api } from '../api.js'
import {
  Stack, Title, Table, Text, TextInput, Button, Group, Badge, Skeleton, Alert
} from '@mantine/core'
import { notifications } from '@mantine/notifications'

const DESCRIPTIONS = {
  waf_block_score:       'Min threat score to block a request (0–100)',
  waf_detect_score:      'Min threat score to log (not block) a request',
  waf_paranoia_level:    'WAF paranoia level: 1=essential, 2=moderate (default), 3=aggressive, 4=paranoid',
  alert_block_threshold: 'Blocked requests/minute threshold to trigger alerts (default 20)',
  rate_limit_rps:        'Burst request rate per IP (req/sec)',
  rate_limit_window:     'Window in seconds for rate-limit counting',
  log_retention_days:    'How many days access logs are kept',
  upstream_timeout:      'Timeout in seconds for upstream HTTP calls',
  health_check_interval: 'Upstream health check interval in seconds',
  acme_email:            'Contact email for Let\'s Encrypt account',
}

export default function Settings() {
  const [map, setMap]         = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [editing, setEditing] = useState({})
  const [saving, setSaving]   = useState({})

  const load = () => {
    setLoading(true)
    api.getAll().then(data => {
      const m = {}
      if (Array.isArray(data)) data.forEach(e => { m[e.key] = e.value })
      else Object.assign(m, data)
      setMap(m)
    }).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  function startEdit(key) { setEditing(e => ({...e, [key]: String(map[key] ?? '')})) }
  function cancelEdit(key) { setEditing(e => { const n={...e}; delete n[key]; return n }) }

  async function save(key) {
    setSaving(s => ({...s,[key]:true}))
    try {
      await api.set(key, editing[key])
      setMap(m => ({...m,[key]:editing[key]}))
      cancelEdit(key)
      notifications.show({ message: `${key} saved`, color: 'teal' })
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    } finally { setSaving(s => ({...s,[key]:false})) }
  }

  if (loading) return <Skeleton h={300} />
  if (error)   return <Alert color="red">{error}</Alert>

  const keys = Object.keys(map).length > 0 ? Object.keys(map) : Object.keys(DESCRIPTIONS)

  return (
    <Stack>
      <Title order={2}>Settings</Title>
      <Table withTableBorder withColumnBorders>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Key</Table.Th><Table.Th>Value</Table.Th>
            <Table.Th>Description</Table.Th><Table.Th w={140}/>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {keys.map(key => {
            const isEditing = key in editing
            return (
              <Table.Tr key={key}>
                <Table.Td><Text ff="monospace" size="sm">{key}</Text></Table.Td>
                <Table.Td>
                  {isEditing ? (
                    <TextInput
                      size="xs" value={editing[key]}
                      onChange={e => setEditing(d=>({...d,[key]:e.target.value}))}
                      onKeyDown={e => { if (e.key==='Enter') save(key); if (e.key==='Escape') cancelEdit(key) }}
                      autoFocus
                    />
                  ) : (
                    <Text ff="monospace" size="sm">{String(map[key] ?? '')}</Text>
                  )}
                </Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{DESCRIPTIONS[key] ?? ''}</Text></Table.Td>
                <Table.Td>
                  {isEditing ? (
                    <Group gap="xs">
                      <Button size="xs" loading={saving[key]} onClick={() => save(key)}>Save</Button>
                      <Button size="xs" variant="default" onClick={() => cancelEdit(key)}>Cancel</Button>
                    </Group>
                  ) : (
                    <Button size="xs" variant="subtle" onClick={() => startEdit(key)}>Edit</Button>
                  )}
                </Table.Td>
              </Table.Tr>
            )
          })}
        </Table.Tbody>
      </Table>
    </Stack>
  )
}
