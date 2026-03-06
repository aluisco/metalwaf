import { useEffect, useState, useCallback } from 'react'
import { sites as sitesApi, rules as api } from '../api.js'
import {
  Stack, Title, Group, Button, Table, Badge, Modal,
  TextInput, Select, Checkbox, Text, SimpleGrid, Skeleton, Alert, NumberInput,
  Switch, ThemeIcon, Tooltip, Tabs, Textarea, ScrollArea,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'
import {
  IconShieldBolt, IconPlus, IconPencil, IconTrash,
  IconDownload, IconUpload, IconShield,
} from '@tabler/icons-react'
import ConfirmModal from '../components/ConfirmModal.jsx'

const FIELDS    = ['uri','query','body','ip','user_agent','method','header']
const OPERATORS = ['contains','not_contains','regex','equals','startswith','endswith','cidr']
const ACTIONS   = [
  { value: 'block',  label: 'Block'  },
  { value: 'detect', label: 'Detect' },
  { value: 'allow',  label: 'Allow'  },
]
const FIELD_OPT    = FIELDS.map(f => ({ value: f, label: f }))
const OPERATOR_OPT = OPERATORS.map(o => ({ value: o, label: o }))

const EMPTY = { name:'', description:'', field:'uri', operator:'contains', value:'', action:'block', score:50, enabled:true, site_id:null }

export default function WAFRules() {
  const [siteList, setSiteList]     = useState([])
  const [siteId, setSiteId]         = useState(null)
  const [list, setList]             = useState([])
  const [builtin, setBuiltin]       = useState([])
  const [categories, setCategories] = useState([])
  const [catFilter, setCatFilter]   = useState(null)
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState('')
  const [saving, setSaving]         = useState(false)
  const [current, setCurrent]       = useState(null)
  const [form, setForm]             = useState(EMPTY)
  const [opened, { open, close }]                           = useDisclosure()
  const [importOpen, { open: openImport, close: closeImport }] = useDisclosure()
  const [importText, setImportText] = useState('')
  const [importing, setImporting]   = useState(false)
  const [delTarget, setDelTarget]   = useState(null)

  useEffect(() => { sitesApi.list().then(setSiteList).catch(() => {}) }, [])

  useEffect(() => {
    api.builtin().then(setBuiltin).catch(() => {})
    api.categories().then(setCategories).catch(() => {})
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    api.list()
      .then(rows => setList(siteId == null ? rows.filter(r => !r.site_id) : rows.filter(r => r.site_id === siteId)))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [siteId])
  useEffect(load, [load])

  function startCreate() { setCurrent(null); setForm({...EMPTY, site_id: siteId}); open() }
  function startEdit(r) {
    setCurrent(r)
    setForm({ name: r.name, description: r.description ?? '', field: r.field, operator: r.operator, value: r.value, action: r.action, score: r.score, enabled: r.enabled, site_id: r.site_id })
    open()
  }

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
    try { await api.delete(r.id); load(); notifications.show({ message: 'Rule deleted', color: 'teal' }) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  async function doExport() {
    try {
      const data = await api.export()
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url; a.download = 'metalwaf-rules.json'; a.click()
      URL.revokeObjectURL(url)
    } catch (err) { notifications.show({ title: 'Export failed', message: err.message, color: 'red' }) }
  }

  async function doImport() {
    setImporting(true)
    try {
      let payload
      try { payload = JSON.parse(importText) } catch { throw new Error('Invalid JSON') }
      const result = await api.import(payload)
      closeImport(); setImportText(''); load()
      notifications.show({
        message: `Imported ${result.imported} rule(s)` + (result.failed ? `, ${result.failed} failed` : ''),
        color: result.failed > 0 ? 'yellow' : 'teal',
      })
    } catch (err) { notifications.show({ title: 'Import failed', message: err.message, color: 'red' }) }
    finally { setImporting(false) }
  }

  const siteOptions = [
    { value: '__global__', label: 'Global (no site)' },
    ...siteList.map(s => ({ value: String(s.id), label: s.name })),
  ]

  const visibleBuiltin = catFilter ? builtin.filter(r => r.category === catFilter) : builtin

  if (loading && list.length === 0 && builtin.length === 0) return <Skeleton h={300} />

  return (
    <Stack>
      <Group gap="xs">
        <ThemeIcon size={32} variant="light" color="orange" radius="md">
          <IconShieldBolt size={18} />
        </ThemeIcon>
        <Title order={2}>WAF Rules</Title>
      </Group>

      {error && <Alert color="red">{error}</Alert>}

      <Tabs defaultValue="custom">
        <Tabs.List>
          <Tabs.Tab value="custom" leftSection={<IconPencil size={14} />}>
            Custom Rules <Badge size="xs" ml={4} color="gray">{list.length}</Badge>
          </Tabs.Tab>
          <Tabs.Tab value="builtin" leftSection={<IconShield size={14} />}>
            Built-in Rules <Badge size="xs" ml={4} color="orange">{builtin.length}</Badge>
          </Tabs.Tab>
        </Tabs.List>

        {/* ─── Custom Rules ────────────────────────────────────────── */}
        <Tabs.Panel value="custom" pt="md">
          <Group justify="space-between" mb="sm">
            <Select
              size="sm" data={siteOptions} w={200}
              value={siteId == null ? '__global__' : String(siteId)}
              onChange={v => setSiteId(v === '__global__' ? null : +v)}
            />
            <Group gap="xs">
              <Tooltip label="Export all custom rules as JSON">
                <Button size="sm" variant="default" leftSection={<IconDownload size={14} />} onClick={doExport}>Export</Button>
              </Tooltip>
              <Button size="sm" variant="default" leftSection={<IconUpload size={14} />} onClick={openImport}>Import</Button>
              <Button size="sm" leftSection={<IconPlus size={15} />} onClick={startCreate}>New rule</Button>
            </Group>
          </Group>

          {list.length === 0 ? (
            <Text c="dimmed">No custom rules found. Click "New rule" to create one.</Text>
          ) : (
            <ScrollArea>
              <Table striped withTableBorder withColumnBorders>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Name</Table.Th>
                    <Table.Th>Field</Table.Th>
                    <Table.Th>Operator</Table.Th>
                    <Table.Th>Value</Table.Th>
                    <Table.Th>Action</Table.Th>
                    <Table.Th>Score</Table.Th>
                    <Table.Th>State</Table.Th>
                    <Table.Th>Actions</Table.Th>
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
                      <Table.Td maw={180} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <Text ff="monospace" size="xs">{r.value}</Text>
                      </Table.Td>
                      <Table.Td><ActionBadge action={r.action} /></Table.Td>
                      <Table.Td>{r.score}</Table.Td>
                      <Table.Td>
                        <Switch checked={r.enabled} onChange={() => toggleEnabled(r)} size="sm" color="teal" />
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          <Tooltip label="Edit rule">
                            <Button size="xs" variant="subtle" px={6} onClick={() => startEdit(r)}>
                              <IconPencil size={14} />
                            </Button>
                          </Tooltip>
                          <Tooltip label="Delete rule">
                            <Button size="xs" variant="subtle" color="red" px={6} onClick={() => setDelTarget(r)}>
                              <IconTrash size={14} />
                            </Button>
                          </Tooltip>
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </ScrollArea>
          )}
        </Tabs.Panel>

        {/* ─── Built-in Rules ──────────────────────────────────────── */}
        <Tabs.Panel value="builtin" pt="md">
          {categories.length > 0 && (
            <Group gap="xs" mb="sm">
              <Badge
                variant={!catFilter ? 'filled' : 'light'} color="gray"
                style={{ cursor: 'pointer' }} onClick={() => setCatFilter(null)}
              >All</Badge>
              {categories.map(c => (
                <Badge
                  key={c.category}
                  variant={catFilter === c.category ? 'filled' : 'light'}
                  color="orange"
                  style={{ cursor: 'pointer' }}
                  onClick={() => setCatFilter(catFilter === c.category ? null : c.category)}
                >
                  {c.category} ({c.builtin})
                </Badge>
              ))}
            </Group>
          )}
          <ScrollArea>
            <Table striped withTableBorder withColumnBorders>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Category</Table.Th>
                  <Table.Th>Field</Table.Th>
                  <Table.Th>Value</Table.Th>
                  <Table.Th>Action</Table.Th>
                  <Table.Th>Score</Table.Th>
                  <Table.Th>Level</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {visibleBuiltin.map(r => (
                  <Table.Tr key={r.name + '_' + r.field}>
                    <Table.Td><Text size="sm" fw={500}>{r.name}</Text></Table.Td>
                    <Table.Td><Badge size="xs" color="orange" variant="outline">{r.category}</Badge></Table.Td>
                    <Table.Td><Text ff="monospace" size="xs">{r.field}</Text></Table.Td>
                    <Table.Td maw={220} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <Text ff="monospace" size="xs">{r.value}</Text>
                    </Table.Td>
                    <Table.Td><ActionBadge action={r.action} /></Table.Td>
                    <Table.Td>{r.score}</Table.Td>
                    <Table.Td>
                      <Badge size="xs" color={r.level <= 1 ? 'red' : r.level === 2 ? 'orange' : 'gray'} variant="light">
                        L{r.level}
                      </Badge>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Tabs.Panel>
      </Tabs>

      {/* ─── Create / Edit Modal ─────────────────────────────────── */}
      <Modal opened={opened} onClose={close} title={current ? 'Edit WAF rule' : 'New WAF rule'} size="lg">
        <form onSubmit={save}>
          <Stack>
            <SimpleGrid cols={2}>
              <TextInput label="Name" value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))} required />
              <NumberInput label="Score (0–1000)" min={0} max={1000} value={form.score} onChange={v => setForm(f => ({...f, score: +v}))} />
            </SimpleGrid>
            <TextInput label="Description (optional)" value={form.description} onChange={e => setForm(f => ({...f, description: e.target.value}))} />
            <SimpleGrid cols={2}>
              <Select label="Field"    data={FIELD_OPT}    value={form.field}    onChange={v => setForm(f => ({...f, field: v}))} />
              <Select label="Operator" data={OPERATOR_OPT} value={form.operator} onChange={v => setForm(f => ({...f, operator: v}))} />
            </SimpleGrid>
            <TextInput
              label="Value"
              value={form.value}
              onChange={e => setForm(f => ({...f, value: e.target.value}))}
              required
              placeholder="Regex pattern, string, or CIDR (e.g. 192.168.0.0/16)"
            />
            <SimpleGrid cols={2}>
              <Select label="Action" data={ACTIONS} value={form.action} onChange={v => setForm(f => ({...f, action: v}))} />
              <Checkbox label="Enabled" mt="xl" checked={form.enabled} onChange={e => setForm(f => ({...f, enabled: e.target.checked}))} />
            </SimpleGrid>
            <Group justify="flex-end">
              <Button variant="default" onClick={close}>Cancel</Button>
              <Button type="submit" loading={saving}>Save</Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      {/* ─── Import Modal ────────────────────────────────────────── */}
      <Modal opened={importOpen} onClose={closeImport} title="Import WAF rules" size="lg">
        <Stack>
          <Text size="sm" c="dimmed">
            Paste exported JSON below. Accepts the full export envelope{' '}
            <code>{'{"rules":[...]}'}</code> or just the raw array.
          </Text>
          <Textarea
            autosize minRows={10} maxRows={20} ff="monospace" fz="xs"
            value={importText}
            onChange={e => setImportText(e.target.value)}
            placeholder={'{"rules":[{"name":"My block","field":"uri","operator":"contains","value":"/payload","action":"block","score":50}]}'}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={closeImport}>Cancel</Button>
            <Button loading={importing} disabled={!importText.trim()} onClick={doImport}>Import</Button>
          </Group>
        </Stack>
      </Modal>

      <ConfirmModal
        opened={!!delTarget}
        onClose={() => setDelTarget(null)}
        onConfirm={() => remove(delTarget)}
        title="Delete rule"
        message={`Delete rule "${delTarget?.name}"? This cannot be undone.`}
      />
    </Stack>
  )
}

function ActionBadge({ action }) {
  const map = { block: 'red', detect: 'yellow', allow: 'teal' }
  return <Badge color={map[action] ?? 'gray'} variant="light">{action}</Badge>
}

