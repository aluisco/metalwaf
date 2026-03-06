import { useEffect, useState } from 'react'
import { sites as sitesApi, rules as api } from '../api.js'
import {
  Stack, Title, Group, Button, Table, Badge, Modal,
  TextInput, Select, Checkbox, Text, SimpleGrid, Skeleton, Alert, NumberInput
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'

const FIELDS    = ['url','uri','method','header','body','ip','user_agent']
const OPERATORS = ['contains','regex','equals','starts_with','ends_with','ip_in_list']
const ACTIONS   = [
  { value: 'block', label: 'Block' },
  { value: 'log',   label: 'Log'   },
  { value: 'allow', label: 'Allow' },
]
const FIELD_OPT    = FIELDS.map(f => ({ value: f, label: f }))
const OPERATOR_OPT = OPERATORS.map(o => ({ value: o, label: o }))

const EMPTY = { name:'', description:'', field:'uri', operator:'contains', pattern:'', action:'block', score:50, enabled:true, site_id:null }

export default function WAFRules() {
  const [siteList, setSiteList]   = useState([])
  const [siteId, setSiteId]       = useState(null)
  const [list, setList]           = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [saving, setSaving]       = useState(false)
  const [current, setCurrent]     = useState(null)
  const [form, setForm]           = useState(EMPTY)
  const [opened, { open, close }] = useDisclosure()

  useEffect(() => { sitesApi.list().then(setSiteList).catch(() => {}) }, [])

  const load = () => {
    setLoading(true)
    api.list().then(rows => {
      setList(siteId == null ? rows.filter(r => !r.site_id) : rows.filter(r => r.site_id === siteId))
    }).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [siteId])

  function startCreate() { setCurrent(null); setForm({...EMPTY, site_id: siteId}); open() }
  function startEdit(r)  { setCurrent(r); setForm({ name:r.name, description:r.description??'', field:r.field, operator:r.operator, pattern:r.pattern, action:r.action, score:r.score, enabled:r.enabled, site_id:r.site_id }); open() }

  async function save(e) {
    e.preventDefault(); setSaving(true)
    try {
      if (!current) await api.create(form); else await api.update(current.id, form)
      close(); load()
      notifications.show({ message: current ? 'Rule updated' : 'Rule created', color: 'teal' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setSaving(false) }
  }

  async function toggleEnabled(r) {
    try { await api.update(r.id, {...r, enabled: !r.enabled}); load() }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  async function remove(r) {
    if (!confirm(`Delete rule "${r.name}"?`)) return
    try { await api.delete(r.id); load(); notifications.show({ message: 'Rule deleted', color: 'teal' }) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  const siteOptions = [
    { value: '__global__', label: 'Global (no site)' },
    ...siteList.map(s => ({ value: String(s.id), label: s.name })),
  ]

  if (loading) return <Skeleton h={300} />

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>WAF Rules</Title>
        <Group gap="sm">
          <Select
            size="sm" data={siteOptions} w={200}
            value={siteId == null ? '__global__' : String(siteId)}
            onChange={v => setSiteId(v === '__global__' ? null : +v)}
          />
          <Button size="sm" onClick={startCreate}>+ New rule</Button>
        </Group>
      </Group>

      {error && <Alert color="red">{error}</Alert>}

      {list.length === 0 ? (
        <Text c="dimmed">No rules found.</Text>
      ) : (
        <Table striped withTableBorder withColumnBorders>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th><Table.Th>Field</Table.Th><Table.Th>Operator</Table.Th>
              <Table.Th>Pattern</Table.Th><Table.Th>Action</Table.Th><Table.Th>Score</Table.Th>
              <Table.Th>State</Table.Th><Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {list.map(r => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <Text fw={600} size="sm">{r.name}</Text>
                  {r.description && <Text size="xs" c="dimmed">{r.description}</Text>}
                </Table.Td>
                <Table.Td><Text ff="monospace" size="sm">{r.field}</Text></Table.Td>
                <Table.Td><Badge color="blue" variant="light" size="sm">{r.operator}</Badge></Table.Td>
                <Table.Td maw={180} style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                  <Text ff="monospace" size="xs">{r.pattern}</Text>
                </Table.Td>
                <Table.Td><ActionBadge action={r.action} /></Table.Td>
                <Table.Td>{r.score}</Table.Td>
                <Table.Td>
                  <Badge color={r.enabled ? 'teal' : 'gray'} variant="light"
                    style={{ cursor: 'pointer' }} onClick={() => toggleEnabled(r)}>
                    {r.enabled ? 'enabled' : 'disabled'}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Group gap="xs">
                    <Button size="xs" variant="light" onClick={() => startEdit(r)}>Edit</Button>
                    <Button size="xs" variant="light" color="red" onClick={() => remove(r)}>Delete</Button>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal opened={opened} onClose={close} title={current ? 'Edit WAF rule' : 'New WAF rule'} size="lg">
        <form onSubmit={save}>
          <Stack>
            <SimpleGrid cols={2}>
              <TextInput label="Name" value={form.name} onChange={e => setForm(f=>({...f,name:e.target.value}))} required />
              <NumberInput label="Score (0–100)" min={0} max={100} value={form.score} onChange={v => setForm(f=>({...f,score:+v}))} />
            </SimpleGrid>
            <TextInput label="Description (optional)" value={form.description} onChange={e => setForm(f=>({...f,description:e.target.value}))} />
            <SimpleGrid cols={2}>
              <Select label="Field"    data={FIELD_OPT}    value={form.field}    onChange={v => setForm(f=>({...f,field:v}))} />
              <Select label="Operator" data={OPERATOR_OPT} value={form.operator} onChange={v => setForm(f=>({...f,operator:v}))} />
            </SimpleGrid>
            <TextInput label="Pattern" value={form.pattern} onChange={e => setForm(f=>({...f,pattern:e.target.value}))} required />
            <SimpleGrid cols={2}>
              <Select label="Action" data={ACTIONS} value={form.action} onChange={v => setForm(f=>({...f,action:v}))} />
              <Checkbox label="Enabled" mt="xl" checked={form.enabled} onChange={e => setForm(f=>({...f,enabled:e.target.checked}))} />
            </SimpleGrid>
            <Group justify="flex-end">
              <Button variant="default" onClick={close}>Cancel</Button>
              <Button type="submit" loading={saving}>Save</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  )
}

function ActionBadge({ action }) {
  const map = { block: 'red', log: 'yellow', allow: 'teal' }
  return <Badge color={map[action] ?? 'gray'} variant="light">{action}</Badge>
}
