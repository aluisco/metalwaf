import { useEffect, useState } from 'react'
import { ipLists as api, sites as sitesApi } from '../api.js'
import {
  Stack, Title, Group, Button, Table, Tabs, Badge, Modal,
  TextInput, Select, Text, Skeleton, Alert, Tooltip, ActionIcon,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'
import { IconShieldLock, IconPlus, IconTrash, IconAlertCircle } from '@tabler/icons-react'
import ConfirmModal from '../components/ConfirmModal.jsx'

const EMPTY = { type: 'block', cidr: '', comment: '', site_id: null }

export default function IPLists() {
  const [list, setList]           = useState([])
  const [siteList, setSiteList]   = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [saving, setSaving]       = useState(false)
  const [activeTab, setActiveTab] = useState('block')
  const [form, setForm]           = useState(EMPTY)
  const [opened, { open, close }] = useDisclosure()
  const [delTarget, setDelTarget] = useState(null)

  useEffect(() => {
    sitesApi.list().then(setSiteList).catch(() => {})
  }, [])

  const load = () => {
    setLoading(true)
    api.list()
      .then(rows => setList(rows ?? []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }
  useEffect(load, [])

  const filtered = list.filter(e => e.type === activeTab)

  function startCreate() {
    setForm({ ...EMPTY, type: activeTab })
    open()
  }

  async function save(e) {
    e.preventDefault()
    if (!form.cidr.trim()) {
      notifications.show({ color: 'red', message: 'IP / CIDR is required' })
      return
    }
    setSaving(true)
    try {
      await api.create({
        type: form.type,
        cidr: form.cidr.trim(),
        comment: form.comment.trim(),
        site_id: form.site_id || null,
      })
      notifications.show({ color: 'green', message: 'Entry added' })
      close()
      load()
    } catch (err) {
      notifications.show({ color: 'red', message: err.message })
    } finally {
      setSaving(false)
    }
  }

  async function confirmDelete() {
    if (!delTarget) return
    try {
      await api.delete(delTarget.id)
      notifications.show({ color: 'green', message: 'Entry removed' })
      setDelTarget(null)
      load()
    } catch (err) {
      notifications.show({ color: 'red', message: err.message })
    }
  }

  const siteOptions = [
    { value: '', label: '— Global (all sites) —' },
    ...siteList.map(s => ({ value: s.id, label: s.name })),
  ]

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Group gap="sm">
          <IconShieldLock size={28} />
          <Title order={2}>IP Access Control</Title>
        </Group>
        <Button leftSection={<IconPlus size={16} />} onClick={startCreate}>
          Add Entry
        </Button>
      </Group>

      {error && (
        <Alert icon={<IconAlertCircle size={16} />} color="red" title="Error">
          {error}
        </Alert>
      )}

      <Tabs value={activeTab} onChange={setActiveTab}>
        <Tabs.List>
          <Tabs.Tab value="block">
            <Badge color="red" variant="light" mr={6}>
              {list.filter(e => e.type === 'block').length}
            </Badge>
            Blocklist
          </Tabs.Tab>
          <Tabs.Tab value="allow">
            <Badge color="green" variant="light" mr={6}>
              {list.filter(e => e.type === 'allow').length}
            </Badge>
            Allowlist
          </Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value={activeTab} pt="md">
          {loading ? (
            <Stack gap="xs">
              {[...Array(4)].map((_, i) => <Skeleton key={i} height={36} />)}
            </Stack>
          ) : (
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>IP / CIDR</Table.Th>
                  <Table.Th>Scope</Table.Th>
                  <Table.Th>Comment</Table.Th>
                  <Table.Th>Added</Table.Th>
                  <Table.Th w={60} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {filtered.length === 0 ? (
                  <Table.Tr>
                    <Table.Td colSpan={5}>
                      <Text ta="center" c="dimmed" py="xl">
                        No {activeTab}list entries yet
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ) : filtered.map(entry => {
                  const site = siteList.find(s => s.id === entry.site_id)
                  return (
                    <Table.Tr key={entry.id}>
                      <Table.Td>
                        <Text ff="monospace">{entry.cidr}</Text>
                      </Table.Td>
                      <Table.Td>
                        {site
                          ? <Badge variant="outline">{site.name}</Badge>
                          : <Badge color="gray" variant="light">Global</Badge>}
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" c={entry.comment ? undefined : 'dimmed'}>
                          {entry.comment || '—'}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs" c="dimmed">
                          {new Date(entry.created_at).toLocaleDateString()}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Tooltip label="Remove">
                          <ActionIcon
                            color="red"
                            variant="subtle"
                            onClick={() => setDelTarget(entry)}
                          >
                            <IconTrash size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Table.Td>
                    </Table.Tr>
                  )
                })}
              </Table.Tbody>
            </Table>
          )}
        </Tabs.Panel>
      </Tabs>

      {/* Add modal */}
      <Modal
        opened={opened}
        onClose={close}
        title={<Group gap="xs"><IconShieldLock size={18} /><Text fw={600}>Add IP List Entry</Text></Group>}
      >
        <form onSubmit={save}>
          <Stack gap="sm">
            <Select
              label="Type"
              data={[
                { value: 'block', label: 'Block — deny access' },
                { value: 'allow', label: 'Allow — bypass WAF & rate limit' },
              ]}
              value={form.type}
              onChange={v => setForm(f => ({ ...f, type: v }))}
              required
            />
            <TextInput
              label="IP or CIDR"
              placeholder="e.g. 1.2.3.4 or 10.0.0.0/8"
              value={form.cidr}
              onChange={e => setForm(f => ({ ...f, cidr: e.target.value }))}
              required
            />
            <Select
              label="Scope"
              description="Leave blank to apply globally to all sites"
              data={siteOptions}
              value={form.site_id ?? ''}
              onChange={v => setForm(f => ({ ...f, site_id: v || null }))}
              clearable
            />
            <TextInput
              label="Comment"
              placeholder="Optional note"
              value={form.comment}
              onChange={e => setForm(f => ({ ...f, comment: e.target.value }))}
            />
            <Group justify="flex-end" mt="md">
              <Button variant="default" onClick={close}>Cancel</Button>
              <Button type="submit" loading={saving}>Add Entry</Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      {/* Delete confirm */}
      <ConfirmModal
        opened={!!delTarget}
        onClose={() => setDelTarget(null)}
        onConfirm={confirmDelete}
        title="Remove IP List Entry"
        message={delTarget ? `Remove ${delTarget.type}list entry for ${delTarget.cidr}?` : ''}
        confirmLabel="Remove"
        confirmColor="red"
      />
    </Stack>
  )
}
