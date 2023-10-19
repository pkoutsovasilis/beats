package kprobes

type EventType uint8

const (
	EventTypeInvalid EventType = iota
	EventTypeCreated
	EventTypeUpdated
	EventTypeDeleted
)

type FilesystemEvent struct {
	Type     EventType
	FilePath string
	PID      uint32
}
