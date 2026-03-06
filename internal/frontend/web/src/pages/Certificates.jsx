import { useEffect, useState } from 'react'
import { certs as api } from '../api.js'
import {
  Stack, Title, Group, Button, Table, Badge, Modal,
  Textarea, TextInput, Checkbox, Text, Skeleton, Alert
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'
import ConfirmModal from '../components/ConfirmModal.jsx'

export default function Certificates() {
  const [list, setList]       = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [saving, setSaving]   = useState(false)
  const [uploadOpened, { open: openUpload, close: closeUpload }] = useDisclosure()
  const [acmeOpened,   { open: openAcme,   close: closeAcme   }] = useDisclosure()
  const [upForm, setUpForm]   = useState({ cert_pem:'', key_pem:'', auto_renew:false })
  const [acmeDomain, setAcmeDomain] = useState('')
  const [delTarget, setDelTarget] = useState(null)

  const load = () => {
    setLoading(true)
    api.list().then(setList).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  async function uploadCert(e) {
    e.preventDefault(); setSaving(true)
    try {
      await api.upload(upForm)
      closeUpload()
      setUpForm({ cert_pem:'', key_pem:'', auto_renew:false })
      load()
      notifications.show({ message: 'Certificate uploaded', color: 'teal' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setSaving(false) }
  }

  async function requestACME(e) {
    e.preventDefault(); setSaving(true)
    try {
      await api.requestACME({ domain: acmeDomain })
      closeAcme(); setAcmeDomain(''); load()
      notifications.show({ message: 'Certificate requested', color: 'teal' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setSaving(false) }
  }

  async function remove(c) {
    try { await api.delete(c.id); load(); notifications.show({ message: 'Certificate revoked', color: 'teal' }) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  if (loading) return <Skeleton h={200} />
  if (error)   return <Alert color="red">{error}</Alert>

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Certificates</Title>
        <Group gap="sm">
          <Button size="sm" variant="default" onClick={openAcme}>
            Request Let&apos;s Encrypt
          </Button>
          <Button size="sm" onClick={openUpload}>+ Upload</Button>
        </Group>
      </Group>

      {list.length === 0 ? (
        <Text c="dimmed">No certificates found.</Text>
      ) : (
        <Table striped withTableBorder withColumnBorders>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Domain</Table.Th><Table.Th>Source</Table.Th>
              <Table.Th>Expires</Table.Th><Table.Th>Auto-Renew</Table.Th><Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {list.map(c => (
              <Table.Tr key={c.id}>
                <Table.Td><Text ff="monospace" size="sm">{c.domain}</Text></Table.Td>
                <Table.Td><SourceBadge source={c.source}/></Table.Td>
                <Table.Td><ExpiryBadge expiry={c.expires_at}/></Table.Td>
                <Table.Td>{c.auto_renew ? '✓' : '—'}</Table.Td>
                <Table.Td>
                  <Button size="xs" variant="light" color="red" onClick={() => setDelTarget(c)}>Revoke</Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      {/* Upload modal */}
      <Modal opened={uploadOpened} onClose={closeUpload} title="Upload certificate">
        <form onSubmit={uploadCert}>
          <Stack>
            <Textarea
              label="Certificate PEM" rows={6}
              styles={{ input: { fontFamily: 'monospace', fontSize: 11 } }}
              placeholder="-----BEGIN CERTIFICATE-----"
              value={upForm.cert_pem}
              onChange={e => setUpForm(f=>({...f,cert_pem:e.target.value}))}
              required
            />
            <Textarea
              label="Private key PEM" rows={6}
              styles={{ input: { fontFamily: 'monospace', fontSize: 11 } }}
              placeholder="-----BEGIN EC PRIVATE KEY-----"
              value={upForm.key_pem}
              onChange={e => setUpForm(f=>({...f,key_pem:e.target.value}))}
              required
            />
            <Checkbox
              label="Auto-renew when possible"
              checked={upForm.auto_renew}
              onChange={e => setUpForm(f=>({...f,auto_renew:e.target.checked}))}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={closeUpload}>Cancel</Button>
              <Button type="submit" loading={saving}>Upload</Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      {/* ACME modal */}
      <Modal opened={acmeOpened} onClose={closeAcme} title="Request Let's Encrypt certificate">
        <form onSubmit={requestACME}>
          <Stack>
            <TextInput
              label="Domain (must be publicly reachable)"
              placeholder="example.com"
              value={acmeDomain}
              onChange={e => setAcmeDomain(e.target.value)}
              required
            />
            <Text size="xs" c="dimmed">
              MetalWAF will complete an HTTP-01 or TLS-ALPN-01 challenge.
              Make sure the domain resolves to this server on port 80 or 443.
            </Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={closeAcme}>Cancel</Button>
              <Button type="submit" loading={saving}>Request</Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <ConfirmModal
        opened={!!delTarget}
        onClose={() => setDelTarget(null)}
        onConfirm={() => remove(delTarget)}
        title="Revoke certificate"
        confirmLabel="Revoke"
        message={`Revoke certificate for "${delTarget?.domain}"? This cannot be undone.`}
      />
    </Stack>
  )
}

function SourceBadge({ source }) {
  if (source === 'letsencrypt') return <Badge color="blue" variant="light">Let&apos;s Encrypt</Badge>
  if (source === 'self_signed') return <Badge color="gray" variant="light">self-signed</Badge>
  return <Badge color="gray" variant="light">{source ?? 'manual'}</Badge>
}

function ExpiryBadge({ expiry }) {
  if (!expiry) return <Badge color="gray" variant="light">unknown</Badge>
  const ms   = new Date(expiry) - Date.now()
  const days = Math.floor(ms / 86_400_000)
  const label = `${days}d`
  if (days < 0)  return <Badge color="red" variant="light">expired</Badge>
  if (days < 14) return <Badge color="red" variant="light">{label}</Badge>
  if (days < 30) return <Badge color="yellow" variant="light">{label}</Badge>
  return <Badge color="teal" variant="light">{label}</Badge>
}
