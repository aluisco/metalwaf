import { useEffect, useState } from 'react'
import { sites as api } from '../api.js'
import {
  Stack, Title, Group, Button, Table, Badge, Modal,
  TextInput, Select, Checkbox, Text, Skeleton, Alert
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'

const WAF_MODES = [
  { value: 'off',    label: 'Off'    },
  { value: 'detect', label: 'Detect' },
  { value: 'block',  label: 'Block'  },
]
const EMPTY_SITE = { name: '', domain: '', waf_mode: 'detect', https_only: false, enabled: true }
const EMPTY_UP   = { url: '', weight: 1, enabled: true }

export default function Sites() {
  const [list, setList]       = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [saving, setSaving]   = useState(false)

  const [siteOpened, { open: openSite, close: closeSite }] = useDisclosure()
  const [upOpened,   { open: openUp,   close: closeUp   }] = useDisclosure()
  const [panelOpened,{ open: openPanel,close: closePanel}] = useDisclosure()

  const [current,   setCurrent]   = useState(null)
  const [siteForm,  setSiteForm]  = useState(EMPTY_SITE)
  const [panelSite, setPanelSite] = useState(null)
  const [upList,    setUpList]    = useState([])
  const [currentUp, setCurrentUp] = useState(null)
  const [upForm,    setUpForm]    = useState(EMPTY_UP)

  const load = () => {
    setLoading(true)
    api.list().then(setList).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  function startCreate() { setCurrent(null); setSiteForm(EMPTY_SITE); openSite() }
  function startEdit(s)  { setCurrent(s); setSiteForm({ name: s.name, domain: s.domain, waf_mode: s.waf_mode, https_only: s.https_only, enabled: s.enabled }); openSite() }

  async function saveSite(e) {
    e.preventDefault(); setSaving(true)
    try {
      if (!current) await api.create(siteForm); else await api.update(current.id, siteForm)
      closeSite(); load()
      notifications.show({ message: current ? 'Site updated' : 'Site created', color: 'teal' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setSaving(false) }
  }

  async function deleteSite(s) {
    if (!confirm(`Delete site "${s.name}"?`)) return
    try { await api.delete(s.id); load(); notifications.show({ message: 'Site deleted', color: 'teal' }) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  function openUpstreams(s) {
    setPanelSite(s)
    api.listUpstreams(s.id).then(setUpList).catch(e => notifications.show({ message: e.message, color: 'red' }))
    openPanel()
  }

  function startAddUp()   { setCurrentUp(null); setUpForm(EMPTY_UP); openUp() }
  function startEditUp(u) { setCurrentUp(u); setUpForm({ url: u.url, weight: u.weight, enabled: u.enabled }); openUp() }

  async function saveUpstream(e) {
    e.preventDefault(); setSaving(true)
    try {
      if (!currentUp) await api.createUpstream(panelSite.id, upForm)
      else            await api.updateUpstream(panelSite.id, currentUp.id, upForm)
      closeUp(); api.listUpstreams(panelSite.id).then(setUpList)
      notifications.show({ message: 'Upstream saved', color: 'teal' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setSaving(false) }
  }

  async function deleteUpstream(u) {
    if (!confirm(`Delete upstream "${u.url}"?`)) return
    try { await api.deleteUpstream(panelSite.id, u.id); api.listUpstreams(panelSite.id).then(setUpList) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  if (loading) return <Skeleton h={300} />
  if (error)   return <Alert color="red">{error}</Alert>

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Sites</Title>
        <Button size="sm" onClick={startCreate}>+ New site</Button>
      </Group>

      {list.length === 0 ? (
        <Text c="dimmed">No sites configured yet.</Text>
      ) : (
        <Table striped withTableBorder withColumnBorders>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th><Table.Th>Domain</Table.Th>
              <Table.Th>WAF Mode</Table.Th><Table.Th>HTTPS only</Table.Th>
              <Table.Th>Status</Table.Th><Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {list.map(s => (
              <Table.Tr key={s.id}>
                <Table.Td fw={600}>{s.name}</Table.Td>
                <Table.Td><Text ff="monospace" size="sm">{s.domain}</Text></Table.Td>
                <Table.Td><WafBadge mode={s.waf_mode} /></Table.Td>
                <Table.Td>{s.https_only ? '✓' : '—'}</Table.Td>
                <Table.Td>
                  {s.enabled
                    ? <Badge color="teal" variant="light">active</Badge>
                    : <Badge color="gray" variant="light">disabled</Badge>}
                </Table.Td>
                <Table.Td>
                  <Group gap="xs">
                    <Button size="xs" variant="light" onClick={() => startEdit(s)}>Edit</Button>
                    <Button size="xs" variant="light" color="blue" onClick={() => openUpstreams(s)}>Upstreams</Button>
                    <Button size="xs" variant="light" color="red"  onClick={() => deleteSite(s)}>Delete</Button>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      {/* Site modal */}
      <Modal opened={siteOpened} onClose={closeSite} title={current ? 'Edit site' : 'New site'}>
        <form onSubmit={saveSite}>
          <Stack>
            <TextInput label="Name" value={siteForm.name} onChange={e => setSiteForm(f=>({...f,name:e.target.value}))} required />
            <TextInput label="Domain" placeholder="example.com" value={siteForm.domain} onChange={e => setSiteForm(f=>({...f,domain:e.target.value}))} required />
            <Select label="WAF Mode" data={WAF_MODES} value={siteForm.waf_mode} onChange={v => setSiteForm(f=>({...f,waf_mode:v}))} />
            <Group>
              <Checkbox label="HTTPS only" checked={siteForm.https_only} onChange={e => setSiteForm(f=>({...f,https_only:e.target.checked}))} />
              <Checkbox label="Enabled"    checked={siteForm.enabled}    onChange={e => setSiteForm(f=>({...f,enabled:e.target.checked}))} />
            </Group>
            <Group justify="flex-end">
              <Button variant="default" onClick={closeSite}>Cancel</Button>
              <Button type="submit" loading={saving}>Save</Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      {/* Upstreams panel */}
      <Modal opened={panelOpened} onClose={closePanel} title={`Upstreams — ${panelSite?.name ?? ''}`} size="lg">
        <Stack>
          <Group justify="flex-end">
            <Button size="sm" onClick={startAddUp}>+ Add upstream</Button>
          </Group>
          {upList.length === 0 ? <Text c="dimmed">No upstreams yet.</Text> : (
            <Table withTableBorder>
              <Table.Thead>
                <Table.Tr><Table.Th>URL</Table.Th><Table.Th>Weight</Table.Th><Table.Th>Status</Table.Th><Table.Th /></Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {upList.map(u => (
                  <Table.Tr key={u.id}>
                    <Table.Td><Text ff="monospace" size="sm">{u.url}</Text></Table.Td>
                    <Table.Td>{u.weight}</Table.Td>
                    <Table.Td>{u.enabled ? <Badge color="teal" variant="light">on</Badge> : <Badge color="gray" variant="light">off</Badge>}</Table.Td>
                    <Table.Td>
                      <Group gap="xs">
                        <Button size="xs" variant="light" onClick={() => startEditUp(u)}>Edit</Button>
                        <Button size="xs" variant="light" color="red" onClick={() => deleteUpstream(u)}>✕</Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
        </Stack>
      </Modal>

      {/* Upstream edit modal */}
      <Modal opened={upOpened} onClose={closeUp} title={currentUp ? 'Edit upstream' : 'Add upstream'}>
        <form onSubmit={saveUpstream}>
          <Stack>
            <TextInput label="URL" placeholder="http://10.0.0.1:8080" value={upForm.url} onChange={e => setUpForm(f=>({...f,url:e.target.value}))} required />
            <TextInput label="Weight" type="number" min={1} max={100} value={upForm.weight} onChange={e => setUpForm(f=>({...f,weight:+e.target.value}))} />
            <Checkbox label="Enabled" checked={upForm.enabled} onChange={e => setUpForm(f=>({...f,enabled:e.target.checked}))} />
            <Group justify="flex-end">
              <Button variant="default" onClick={closeUp}>Cancel</Button>
              <Button type="submit" loading={saving}>Save</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  )
}

function WafBadge({ mode }) {
  const map = { block: 'red', detect: 'yellow', off: 'gray' }
  return <Badge color={map[mode] ?? 'gray'} variant="light">{mode}</Badge>
}
