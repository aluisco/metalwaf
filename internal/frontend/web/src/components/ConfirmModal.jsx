import { Modal, Text, Group, Button, Stack, ThemeIcon } from '@mantine/core'
import { IconAlertTriangle } from '@tabler/icons-react'

/**
 * ConfirmModal — a reusable confirmation dialog.
 *
 * Usage:
 *   const [target, setTarget] = useState(null)
 *
 *   <Button onClick={() => setTarget(item)}>Delete</Button>
 *   <ConfirmModal
 *     opened={!!target}
 *     onClose={() => setTarget(null)}
 *     onConfirm={() => doDelete(target)}
 *     title="Delete site"
 *     message={`Delete "${target?.name}"? This cannot be undone.`}
 *   />
 */
export default function ConfirmModal({
  opened,
  onClose,
  onConfirm,
  title = 'Are you sure?',
  message,
  confirmLabel = 'Delete',
  confirmColor = 'red',
}) {
  function handleConfirm() {
    onConfirm()
    onClose()
  }

  return (
    <Modal opened={opened} onClose={onClose} title={title} size="sm" centered withCloseButton>
      <Stack gap="md">
        <Group gap="sm" align="flex-start" wrap="nowrap">
          <ThemeIcon color="red" variant="light" size={36} radius="xl" style={{ flexShrink: 0 }}>
            <IconAlertTriangle size={20} />
          </ThemeIcon>
          <Text size="sm" style={{ paddingTop: 6 }}>
            {message}
          </Text>
        </Group>
        <Group justify="flex-end" gap="sm">
          <Button variant="default" onClick={onClose}>Cancel</Button>
          <Button color={confirmColor} onClick={handleConfirm}>{confirmLabel}</Button>
        </Group>
      </Stack>
    </Modal>
  )
}
