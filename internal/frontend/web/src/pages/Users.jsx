import { useEffect, useState } from 'react'
import { users as api } from '../api.js'
import {
  Stack, Title, Group, Button, Table, Badge, Modal,
  TextInput, PasswordInput, Select, Text, Skeleton, Alert,
  Avatar, ThemeIcon, Tooltip, ActionIcon, Box
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'
import {
  IconUsers, IconPlus, IconPencil, IconTrash,
  IconShieldLock, IconDeviceFloppy
} from '@tabler/icons-react'
import ConfirmModal from '../components/ConfirmModal.jsx'

const ROLE_OPTIONS = [
  { value: 'admin',  label: 'Admin'  },
  { value: 'viewer', label: 'Viewer' },
]

const EMPTY = { username: '', email: '', password: '', role: 'viewer' }

function initials(username) {
  return username.slice(0, 2).toUpperCase()
}

export default function Users() {
  const [list, setList]           = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [saving, setSaving]       = useState(false)
  const [current, setCurrent]     = useState(null)
  const [form, setForm]           = useState(EMPTY)
  const [opened, { open, close }] = useDisclosure()
  const [delTarget, setDelTarget] = useState(null)

  const load = () => {
    setLoading(true)
    api.list().then(setList).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  function startCreate() { setCurrent(null); setForm(EMPTY); open() }
  function startEdit(u) {
    setCurrent(u)
    setForm({ username: u.username, email: u.email ?? '', password: '', role: u.role })
    open()
  }

  async function save(e) {
    e.preventDefault(); setSaving(true)
    try {
      const payload = { email: form.email, role: form.role }
      if (!current) {
        // Create: all fields required
        await api.create({ ...payload, username: form.username, password: form.password })
      } else {
        // Update: password optional (only if filled)
        if (form.password) payload.password = form.password
        await api.update(current.id, payload)
      }
      close(); load()
      notifications.show({ message: current ? 'User updated' : 'User created', color: 'teal' })
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    } finally { setSaving(false) }
  }

  async function doDelete() {
    try {
      await api.delete(delTarget.id); load()
      notifications.show({ message: `User "${delTarget.username}" deleted`, color: 'teal' })
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    }
  }

  async function revokeSessions(u) {
    try {
      await api.revokeSessions(u.id)
      notifications.show({ message: `Sessions revoked for "${u.username}"`, color: 'teal' })
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    }
  }

  if (loading) return <Skeleton h={300} />

  return (
    <Stack>
      <Group justify="space-between">
        <Group gap="xs">
          <ThemeIcon size={32} variant="light" color="violet" radius="md">
            <IconUsers size={18} />
          </ThemeIcon>
          <Title order={2}>Users</Title>
        </Group>
        <Button size="sm" leftSection={<IconPlus size={15} />} onClick={startCreate}>
          New user
        </Button>
      </Group>

      {error && <Alert color="red">{error}</Alert>}

      {list.length === 0 ? (
        <Text c="dimmed">No users found.</Text>
      ) : (
        <Table striped withTableBorder withColumnBorders highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>User</Table.Th>
              <Table.Th>Email</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th>2FA</Table.Th>
              <Table.Th>Created</Table.Th>
              <Table.Th w={140}>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {list.map(u => (
              <Table.Tr
                key={u.id}
                style={{ cursor: 'pointer' }}
                onClick={() => startEdit(u)}
              >
                <Table.Td>
                  <Group gap="sm">
                    <Avatar
                      size={32} radius="xl" color="teal" variant="light"
                    >
                      {initials(u.username)}
                    </Avatar>
                    <Text size="sm" fw={600}>{u.username}</Text>
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" c={u.email ? undefined : 'dimmed'}>{u.email || '—'}</Text>
                </Table.Td>
                <Table.Td>
                  <RoleBadge role={u.role} />
                </Table.Td>
                <Table.Td>
                  <Badge
                    size="sm"
                    color={u.totp_enabled ? 'teal' : 'gray'}
                    variant={u.totp_enabled ? 'light' : 'outline'}
                  >
                    {u.totp_enabled ? '2FA on' : '2FA off'}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                  </Text>
                </Table.Td>
                <Table.Td onClick={e => e.stopPropagation()}>
                  <Group gap={4}>
                    <Tooltip label="Edit user">
                      <ActionIcon variant="subtle" onClick={() => startEdit(u)}>
                        <IconPencil size={15} />
                      </ActionIcon>
                    </Tooltip>
                    <Tooltip label="Revoke all sessions">
                      <ActionIcon variant="subtle" color="orange" onClick={() => revokeSessions(u)}>
                        <IconShieldLock size={15} />
                      </ActionIcon>
                    </Tooltip>
                    <Tooltip label="Delete user">
                      <ActionIcon variant="subtle" color="red" onClick={() => setDelTarget(u)}>
                        <IconTrash size={15} />
                      </ActionIcon>
                    </Tooltip>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      {/* Create / Edit modal */}
      <Modal
        opened={opened}
        onClose={close}
        title={
          <Group gap="xs">
            <IconUsers size={18} />
            <span>{current ? `Edit: ${current.username}` : 'New user'}</span>
          </Group>
        }
        size="sm"
      >
        <form onSubmit={save}>
          <Stack gap="sm">
            {!current && (
              <TextInput
                label="Username" required
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                autoFocus
              />
            )}
            <TextInput
              label="Email"
              value={form.email}
              onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              placeholder="user@example.com"
            />
            <PasswordInput
              label={current ? 'New password (leave blank to keep)' : 'Password'}
              required={!current}
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              description={!current ? 'Min 12 characters' : undefined}
            />
            <Select
              label="Role"
              data={ROLE_OPTIONS}
              value={form.role}
              onChange={v => setForm(f => ({ ...f, role: v }))}
            />
            <Group justify="flex-end" mt="xs">
              <Button variant="default" onClick={close}>Cancel</Button>
              <Button
                type="submit"
                loading={saving}
                leftSection={<IconDeviceFloppy size={15} />}
              >
                {current ? 'Save changes' : 'Create user'}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      {/* Delete confirmation */}
      <ConfirmModal
        opened={!!delTarget}
        onClose={() => setDelTarget(null)}
        onConfirm={doDelete}
        title="Delete user"
        message={`Delete user "${delTarget?.username}"? All their sessions will be revoked and this cannot be undone.`}
      />
    </Stack>
  )
}

function RoleBadge({ role }) {
  return (
    <Badge
      size="sm"
      color={role === 'admin' ? 'violet' : 'blue'}
      variant="light"
    >
      {role}
    </Badge>
  )
}
